@load base/frameworks/broker
@load base/frameworks/deepcluster

module DeepStats;

const DEBUG = T;

export {
    ## The percent of the full threshold value that needs to be met on a
    ## single worker for that worker to send the value to its manager in
    ## order for it to request a global view for that value.  There is no
    ## requirement that the manager requests a global view for the key since
    ## it may opt not to if it requested a global view for the key recently.
    const cluster_request_global_view_percent = 0.2 &redef;

    ## This is to deal with intermediate update overload.  A manager will
    ## only allow this many intermediate update requests to the workers to
    ## be inflight at any given time.  Requested intermediate updates are
    ## currently thrown out and not performed.  In practice this should
    ## hopefully have a minimal effect.
    const max_outstanding_global_views = 10 &redef;

    ## Event sent by the manager in a cluster to initiate the collection of
    ## values for a sumstat.
    global cluster_ss_request: event(uid: string, ss_name: string, cleanup: bool);

    ## This event is sent by the manager in a cluster to initiate the
    ## collection of a single key value from a sumstat.  It's typically used
    ## to get intermediate updates before the break interval triggers to
    ## speed detection of a value crossing a threshold.
    global cluster_get_result: event(uid: string, ss_name: string, key: Key, cleanup: bool);

    ## This event is sent by nodes in response to a
    ## :zeek:id:`SumStats::cluster_get_result` event.
    global cluster_send_result: event(uid: string, ss_name: string, key: Key, result: Result, cleanup: bool);

    ## This is sent by workers to indicate that they crossed the percent
    ## of the current threshold by the percentage defined globally in
    ## :zeek:id:`SumStats::cluster_request_global_view_percent`.
    global cluster_key_intermediate_response: event(ss_name: string, key: DeepStats::Key);

    ## This event is scheduled internally on workers to send result chunks.
    global send_data: event(uid: string, ss_name: string, data: ResultTable, cleanup: bool);

    global get_a_key: event(uid: string, ss_name: string, cleanup: bool &default=F);

    global send_a_key: event(uid: string, ss_name: string, key: Key);
    global send_no_key: event(uid: string, ss_name: string);

    ## This event is generated when a threshold is crossed.
    global cluster_threshold_crossed: event(ss_name: string, key: DeepStats::Key, thold_index: count);
}

# This variable is maintained to know what keys have recently sent or received
# intermediate updates so they don't overwhelm the manager.
global recent_global_view_keys: set[string, Key] &create_expire=1min;

# This variable is maintained by manager nodes as they collect and aggregate
# results.
# Index on a uid.
global stats_keys: table[string] of set[Key] &read_expire=1min
    &expire_func=function(s: table[string] of set[Key], idx: string): interval {
        # XXX Reenable for production
        #Reporter::warning(fmt("SumStat key request for the %s SumStat uid took longer than 1 minute and was automatically cancelled.", idx));
        return 0secs;
    };

# This variable is maintained by manager nodes to track how many "dones" they
# collected per collection unique id.  Once the number of results for a uid
# matches the number of peer nodes that results should be coming from, the
# result is written out and deleted from here.
# Indexed on a uid.
global done_with: table[string] of count &read_expire=1min &default=0;

# This variable is maintained by managers to track intermediate responses as
# they are getting a global view for a certain key.
# Indexed on a uid.
global key_requests: table[string] of Result &read_expire=1min;

# Store uids for dynamic requests here to avoid cleanup on the uid.
# (This needs to be done differently!)
global dynamic_requests: set[string] &read_expire=1min;

# This variable is maintained by managers to prevent overwhelming communication due
# to too many intermediate updates.  Each sumstat is tracked separately so that
# one won't overwhelm and degrade other quieter sumstats.
# Indexed on a sumstat id.
global outstanding_global_views: table[string] of set[string] &read_expire=1min;

# Result tables indexed on a uid that are currently being sent to the
# manager.
global sending_results: table[string] of ResultTable = table() &read_expire=1min;

const zero_time = double_to_time(0.0);

function log(msg: string) {
    if (DEBUG) {
        print(msg);
        flush_all();
    }
}

event zeek_init() &priority=5 {
    log("[sumstats/deep-cluster] Begin zeek_init()");
    log("[sumstats/deep-cluster] Finished zeek_init()");
}

function data_added(ss: SumStat, key: Key, result: Result) {
    log(fmt("[sumstats/deep-cluster] data_added for SumStat '%s' (%s)", ss$name, key2str(key)));

    # WORKER IMPLEMENTATION

    # If an intermediate update for this key was sent recently, don't send it again
    if ([ss$name, key] in recent_global_view_keys)
        return;

    # If val is 5 and global view % is 0.1 (10%), pct_val will be 50.  If that
    # crosses the full threshold then it's a candidate to send as an
    # intermediate update.
    if (check_thresholds(ss, key, result, cluster_request_global_view_percent)) {
        # kick off intermediate update
        if (ss?$group && DeepCluster::is_child_of_group(ss$group)) {
            local _ckir = Broker::make_event(DeepStats::cluster_key_intermediate_response, ss$name, key);
            Broker::publish(DeepCluster::parent_topic_for_group(ss$group), _ckir);
        }
        add recent_global_view_keys[ss$name, key];
    }

    # /WORKER IMPLEMENTATION
}

event DeepStats::finish_epoch(ss: SumStat) {
    log(fmt("[sumstats/deep-cluster] finish_epoch for SumStat '%s'", ss$name));

    local _children: set[string];

    if (network_time() > zero_time) {

        #print fmt("%.6f MANAGER: breaking %s sumstat", network_time(), ss$name);
        local uid = unique_id("");

        if (uid in stats_keys) {
            delete stats_keys[uid];
        }
        stats_keys[uid] = set();

        # Request data from peers.
        if (ss?$group && DeepCluster::is_parent_of_group(ss$group)) {
            local csr = Broker::make_event(DeepStats::cluster_ss_request, uid, ss$name, T);

            _children = DeepCluster::children_for_group(ss$group);
            log(fmt("[sumstats/deep-cluster] Requesting epoch results for group '%s' (%d children)", ss$group, |_children|));
            Broker::publish(DeepCluster::topic_for_group(ss$group), csr);
            for (_c in _children) {
                #log(fmt("[sumstats/deep-cluster] Publishing cluster_ss_request to %s", _c));
                #Broker::publish(_c, csr);
            }
        }

        done_with[uid] = 0;

        #print fmt("get_key by uid: %s", uid);
        event DeepStats::get_a_key(uid, ss$name, T);
    }

    # Schedule the next finish_epoch event.
    schedule ss$epoch { DeepStats::finish_epoch(ss) };
}

event DeepStats::cluster_key_intermediate_response(name: string, key: DeepStats::Key) {
    log(fmt("[sumstats/deep-cluster] cluster_key_intermediate_response for '%s'/'%s'", name, cat(key)));

    # If an intermediate update for this key was handled recently, don't do it again
    if ([name, key] in recent_global_view_keys)
        return;
    add recent_global_view_keys[name, key];

    if (name !in outstanding_global_views) {
        outstanding_global_views[name] = set();
    }
    else if (|outstanding_global_views[name]| > max_outstanding_global_views) {
        # Don't do this intermediate update.  Perhaps at some point in the future
        # we will queue and randomly select from these ignored intermediate
        # update requests.
        return;
    }

    local uid = unique_id("");
    add outstanding_global_views[name][uid];
    done_with[uid] = 0;

    local _ss = stats_store[name];
    if (_ss?$group && DeepCluster::is_parent_of_group(_ss$group)) {
        local _cgr = Broker::make_event(DeepStats::cluster_get_result, uid, name, key, F);

        local _children = DeepCluster::children_for_group(_ss$group);
        for (_c in _children) {
            Broker::publish(_c, _cgr);
        }
    }
}

event DeepStats::cluster_ss_request(uid: string, name: string, cleanup: bool) {
    log(fmt("[sumstats/deep-cluster] cluster_ss_request for '%s'/'%s'", name, uid));

    # Create a back store for the result
    sending_results[uid] = (name in result_store) ? result_store[name] : table();

    # Lookup the actual sumstats and reset it, the reference to the data
    # currently stored will be maintained internally from the
    # sending_results table.
    if (cleanup && name in stats_store) {
        reset(stats_store[name]);
    }
}

event DeepCluster::cluster_send_result(uid: string, name: string, key: Key, result: Result, cleanup: bool) {
    log(fmt("[sumstats/deep-cluster] cluster_send_result for '%s'/'%s'", name, uid));
}

event DeepStats::cluster_get_result(uid: string, name: string, key: Key, cleanup: bool) {
    log(fmt("[sumstats/deep-cluster] cluster_get_result for '%s'/'%s' (cleanup=%s)", name, uid, cat(cleanup)));

    local _parent = DeepCluster::parent_topic_for_group(stats_store[name]$group);
    print(_parent);

    if (cleanup) { # data will implicitly be in sending_results (i know this isn't great)
        if (uid in sending_results && key in sending_results[uid]) {
            # Note: copy is needed to compensate serialization caching issue. This should be
            # changed to something else later.
            local _e1 = Broker::make_event(DeepStats::cluster_send_result, uid, name, key, copy(sending_results[uid][key]), cleanup);
            Broker::publish(_parent, _e1);
            delete sending_results[uid][key];
        }
        else {
            # We need to send an empty response if we don't have the data so that the manager
            # can know that it heard back from all of the workers.
            local _e2 = Broker::make_event(DeepStats::cluster_send_result, uid, name, key, table(), cleanup);
            Broker::publish(_parent, _e2);
        }
    }
    else {
        if (name in result_store && key in result_store[name]) {
            # Note: copy is needed to compensate serialization caching issue. This should be
            # changed to something else later.
            local _e3 = Broker::make_event(DeepStats::cluster_send_result, uid, name, key, copy(result_store[name][key]), cleanup);
            Broker::publish(_parent, _e3);
        }
        else {
            # We need to send an empty response if we don't have the data so that the manager
            # can know that it heard back from all of the workers.
            #local _e4 = Broker::make_event(DeepStats::cluster_send_result, uid, name, key, table(), cleanup);
            Broker::publish(_parent, DeepStats::cluster_send_result, uid, name, key, table(), cleanup);
            #Broker::publish(_parent, _e4);
        }
    }
}
