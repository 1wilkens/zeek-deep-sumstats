@load base/frameworks/broker

module DeepStats;

const DEBUG = T;

function _log(msg: string) {
    if (DEBUG) {
        print(msg);
        flush_all();
    }
}

event zeek_init() &priority=5 {
    _log("[sumstats/main] Begin zeek_init()");

    _log("[sumstats/main] Finished zeek_init()");
}
