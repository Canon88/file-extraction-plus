module Enrichment;

redef record Files::Info += {
    flags:      string      &default="";
};

hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter)
    {    
    if ( rec$flags == "" )
        break;
    }

event zeek_init()
    {
    Log::remove_default_filter(Files::LOG);
    local filter: Log::Filter = [$name="file_extraction", $path="file-extraction"];
    Log::add_filter(Files::LOG, filter);
    }
