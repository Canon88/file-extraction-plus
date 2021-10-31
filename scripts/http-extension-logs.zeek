module Enrichment;

redef record HTTP::Info += {
    records:    bool        &default=F;
    domain:     string      &optional &log;
};

hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter)
    {    
    if ( rec$records == F )
        break;
    }

event zeek_init()
    {
    Log::remove_default_filter(HTTP::LOG);
    local filter: Log::Filter = [$name="http_extraction", $path="http-extraction"];
    Log::add_filter(HTTP::LOG, filter);
    }

export {
    global http: function(f: fa_file): fa_file;
}

function http(f: fa_file): fa_file
    {
    f$http$records = T;
    f$http$domain = f$http$host;
    return f;
    }
