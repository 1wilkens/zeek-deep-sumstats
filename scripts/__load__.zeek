@load ./main
@load ./plugins

# The cluster and deepcluster frameworks must be loaded first.
@load base/frameworks/cluster
@load base/frameworks/deepcluster

# Load either the cluster support script or the non-cluster support script.
@if ( Cluster::is_enabled() )
    @load ./cluster
@else
    @if ( DeepCluster::is_enabled() )
        @load ./deep-cluster
    @else
        @load ./non-cluster
    @endif
@endif
