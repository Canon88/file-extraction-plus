@load ../__load__

module FileExtraction;

const custom_extract: set[string] = {
    ["POST"]
};

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=10
	{
		f$info$flags = "extract";
		break;
	}

hook FileExtraction::http_extract(f: fa_file, meta: fa_metadata) &priority = 5
	{
		break;
	}