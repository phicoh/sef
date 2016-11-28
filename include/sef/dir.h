/*
sef/dir.h

Created:        December 2015 by Philip Homburg <philip@f-src.phicoh.com>

Directory entry
*/

typedef struct sef_dirent
{
	uint64_T	sed_inode;
	uint16_T	sed_extra;
	uint8_T		sed_name[6];
} sef_dirent_T;

/*
 * Directory entries are 64-bit aligned and do not cross block boundaries.
 * sd_extra specifies the number of exta 64-bit chunks in addition to the
 * two for a minimal sized directory entry. The field sd_name is a null
 * terminated string that fits in the space allocated to the directory
 * entry. Empty space is specified by setting sd_inode to zero.
 */

typedef struct sef_dir_sum
{
	uint64_T sds_last_dir;
	uint64_T sds_last_file;
} sef_dir_sum_T;
