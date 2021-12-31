# All configuration must occur within this file.
# All other files may be overwritten during upgrade 
module FileExtraction;

# Configure file-extract_limit
@load ./file-extract_limit

# Configure where extracted files will be stored
redef path = "/data/nta/zeek/extract/";

# Configure 'plugins' that can be loaded
# these are shortcut modules to specify common 
# file extraction policies. Example:
@load ./plugins/extract-custom
@load ./plugins/store-files-by-md5