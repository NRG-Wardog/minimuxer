/* Test CLI: authenticated outputs stay in caller-provided temporary files.
   No payload, certificate, device, or identity data is printed. */
#include "profile_cms.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv) {
 if(argc!=4 || (strcmp(argv[1],"outer") && strcmp(argv[1],"inner"))) return 64;
 FILE *f=fopen(argv[2],"rb"); if(!f) return 65;
 if(fseek(f,0,SEEK_END)) { fclose(f); return 65; }
 long n=ftell(f); if(n<=0 || n>1024*1024 || fseek(f,0,SEEK_SET)) { fclose(f); return 65; }
 unsigned char *bytes=malloc((size_t)n); if(!bytes) {fclose(f);return 65;}
 if(fread(bytes,1,(size_t)n,f)!=(size_t)n) {free(bytes);fclose(f);return 65;}
 fclose(f); v3_cms_content out={0};
 v3_cms_status status=!strcmp(argv[1],"outer")
  ? v3_profile_cms_verify_legacy_outer(bytes,(size_t)n,&out)
  : v3_profile_cms_verify_pinned_inner(bytes,(size_t)n,&out);
 free(bytes);
 if(status!=V3_CMS_OK) {v3_profile_cms_content_free(&out);return (int)status;}
 f=fopen(argv[3],"wb");if(!f){v3_profile_cms_content_free(&out);return 65;}
 int ok=fwrite(out.bytes,1,out.length,f)==out.length;
 if(fclose(f))ok=0;
 v3_profile_cms_content_free(&out);return ok?0:65;
}
