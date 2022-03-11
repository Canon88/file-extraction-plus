module Enrichment;

redef record Files::Info += {
    flags:      string      &default="";
};

hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter)
    {    
    if ( rec$flags == "" )
        break;

    # Extract the real file name
    # Example: /var/mobile/Containers/Data/Application/6532EFD6-7968-498B-9254-3B296A042C32/Documents/pubilsh0.jpg
    local filename = split_string(rec$filename, /\//);
    rec$filename = filename[|filename| -1];
    }

event zeek_init()
    {
    Log::remove_default_filter(Files::LOG);
    local filter: Log::Filter = [$name="file_extraction", $path="file-extraction"];
    Log::add_filter(Files::LOG, filter);
    }
