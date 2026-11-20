/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef I9100_EMMC_ROOT_H
#define I9100_EMMC_ROOT_H
#define I9100_EMMC_ROOT_CMDLINE " rd=i9100-system i9100emmcdata=1"
/* Used only by an explicit internal-root loader. Reject root-token conflicts
 * and insufficient boot_args capacity BEFORE altering any byte. No untrusted
 * path or runtime serial request can choose the target or add extra flags. */
static int i9100_emmc_root_append(char *line,unsigned capacity)
{
 if(!line||!capacity)return 0;
 unsigned end=0;
 while(end<capacity&&line[end])end++;
 if(end==capacity)return 0;
 for(unsigned at=0;at<end;at++)if(!at||line[at-1]==' '||line[at-1]=='\t'){
  if(at+3U<=end&&line[at]=='r'&&line[at+1]=='d'&&line[at+2]=='=')return 0;
  if(at+8U<=end&&line[at]=='r'&&line[at+1]=='o'&&line[at+2]=='o'&&line[at+3]=='t'&&
     line[at+4]=='d'&&line[at+5]=='e'&&line[at+6]=='v'&&line[at+7]=='=')return 0;
 }
 static const char suffix[]=I9100_EMMC_ROOT_CMDLINE;
 if(sizeof(suffix)>capacity-end)return 0;
 for(unsigned n=0;n<sizeof(suffix);n++)line[end+n]=suffix[n];
 return 1;
}
#endif
