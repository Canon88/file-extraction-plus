@load ../__load__

module FileExtraction;

const custom_types: set[string, string] = {
    ["image/jpeg", "hash"],
    ["image/png", "hash"],
    ["image/gif", "hash"],
    ["text/x-php", "extract"],
    ["application/x-executable", "extract"],
    ["application/x-pdf", "extract"],
    ["application/java-archive", "extract"],
    ["application/x-java-applet", "extract"],
    ["application/x-java-jnlp-file", "extract"],
    ["application/msword", "extract"],
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", "extract"],
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "extract"],
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation", "extract"],
};

const custom_extract: set[string] = {
    ["POST"]
};

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority = 5
	{
        if ( [meta$mime_type, "extract"] in custom_types )
            {
            f$info$flags = "extract";
            break;
            }
        
        if ( [meta$mime_type, "hash"] in custom_types )
            {
            f$info$flags = "hash";
            break;
            }
	}

hook FileExtraction::http_extract(f: fa_file, meta: fa_metadata) &priority = 5
	{
        if ( f$http?$host && f$http?$method && f$http?$uri && f$info$is_orig )
            if ( [f$http$method] in custom_extract )
                break;
        f$info$flags = "";
	}