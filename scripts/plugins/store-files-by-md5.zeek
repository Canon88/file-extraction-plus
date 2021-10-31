@load ../__load__
@load policy/frameworks/files/hash-all-files

event file_state_remove(f: fa_file)
	{
	if ( !f$info?$extracted || !f$info?$md5 || FileExtraction::path == "" || !f$info?$enrich)
		return;

	local orig = f$info$extracted;
	
	local split_orig = split_string(f$info$extracted, /\./);
	local extension = split_orig[|split_orig|-1];

	local ntime = fmt("%D", network_time());
	local ndate = sub_bytes(ntime, 1, 10);
	local dest_dir = fmt("%s%s", FileExtraction::path, ndate);
	mkdir(dest_dir);
	local dest = fmt("%s/%s-%s.%s", dest_dir, f$source, f$info$md5, extension);
	local cmd = fmt("mv %s %s", orig, dest);
	when ( local result = Exec::run([$cmd=cmd]) )
	    {
	    }
	if ( rename(orig, dest) )
    	f$info$extracted = dest;
	}