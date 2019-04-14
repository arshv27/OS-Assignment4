#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

static int filesys_inited = 0;



int merkel_tree(const char *pathname, int flags, mode_t mode) {
	char data[2000][21];
	for (int i=0; i<2000; i++) {
		data[i][20]='\0';
	}
	FILE *fp = fopen(pathname, "r");
	int sz = 0;
	if (fp != NULL) {
		//printf("not null\n");
		fseek(fp, 0, SEEK_END);
		sz = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		fclose(fp);
	}else{
		//printf("null\n");
		return 1;
	}
	// printf("%d\n", sz);

	int fd = open(pathname, flags, mode);
	int ptr = 0;
	int ctr = 0;
	while(ptr < sz){
		char d[64];
		char hash[21];
		if (sz-ptr>=64) {
			read(fd, d, 64);
		}
		else{
			char tmp[sz-ptr];
			char tmp2[64-sz+ptr];
			read(fd,tmp, sz-ptr);
			read('a',tmp2,64-sz+ptr);
			strcat(d,tmp);
			strcat(d,tmp2);
		}
		get_sha1_hash(d, 64, hash);
		strncpy(data[ctr], hash, 20);
		ptr += 64;
		ctr++;
	}
	int c=0;
	int index = 0;
	while(ctr>0){
		index = 0;
		c = 0;
		while (c <= ctr) {			
			if (c+1 > ctr) {
				get_sha1_hash(data[c], 20, data[index]);
				// printf("%s\n", data[index] );
				index++;
				c++;
			} else {
				char conchash[41];
				conchash[40]='\0';
				for (int i=0; i<20; i++) {
					conchash[i]=data[c][i];
				}
				for (int i=20; i<40; i++) {
					conchash[i]=data[c+1][i-20];
				}
				c += 2;		
				get_sha1_hash(conchash, 40, data[index]);
				index++;			
			}
		}
		ctr = index-1;
	}

	// size_t len = strlen((const char *) data[0]);
	// printf("Length of data[0] is : %d\n", (int)len);
	close(fd);

	FILE *fp1 = fopen("secure.txt", "a+");
	int has_file = 0;

	char *line = NULL;
	size_t len = 0;
	ssize_t read = 0;
	while ((read = getline(&line, &len, fp1)) != -1) {
		char *name = strtok(line, " ");
		char *hash1 = strtok(NULL, " ");
		char *hash = strtok(hash1, "\n");
		if (!strcmp(pathname, name)) {
			has_file = 1;
			// printf("%s ---%s\n", hash, data[0]);
			if (strcmp(hash, data[0]) != 0) {
				fclose(fp1);
				return -1;
			} 
			else {
				//implement this
				fclose(fp1);
				return 1;
			}
		}
	}
	if (!has_file) {
		printf("%s %s\n", "writing to file", pathname);
		fprintf(fp1, "%s ", pathname);
		fprintf(fp1, "%s\n", data[0]);
		fflush(fp1);
		fclose(fp1);
	}
	return 1;

}

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{
	assert (filesys_inited);
	int c = merkel_tree(pathname, flags, mode);
	if (c == -1) {
		return -1;
	} else {
		return open (pathname, flags, mode);
	}
}

/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
	return lseek (fd, offset, SEEK_SET);
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{
	assert (filesys_inited);
	return write (fd, buf, count);
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);
	return read (fd, buf, count);
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
	return close (fd);
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	filesys_inited = 1;
	char arr[1024][31];
	for (int i=0; i<1024; i++) {
		arr[i][30]='\0';
	}
	if (access("secure.txt",F_OK) == -1) {
		return 0;
	}


	FILE *fp = fopen("secure.txt", "r");
	char *line = NULL;
	size_t len = 0;
	ssize_t read = 0;
	int i = 0;
	int flg = 0;
	while ((read = getline(&line, &len, fp)) != -1) {
		char *name = strtok(line, " ");
		char *hash1 = strtok(NULL, " ");
		char *hash = strtok(hash1, "\n");
		if (access(name,F_OK) == -1) {
			;
		}else{
			int y = merkel_tree(name, O_RDONLY, 0);
			if (y != -1) {
				for (int j = 0; j < 9; j++) {
					arr[i][j] = name[j];
				}
				arr[i][9] = ' ';
				for (int j = 10; j<30; j++) {
					arr[i][j] = hash[j-10];
				}
				i++;
			}
			else {
				flg=1;
			}
		}
	}
	fclose(fp);
	remove("secure.txt");

	FILE *fp1 = fopen("secure.txt", "a+");
	// printf("%d\n", i);
	for (int j=0; j<i; j++) {
		char name[10];
		name[9]='\0';
		for (int k=0; k<9; k++) {
			name[k] = arr[j][k];
			// printf("%s\n",name );
		}
		char hasharr[21];
		hasharr[20]='\0';
		for (int k=10; k<30; k++) {
			hasharr[k-10] = arr[j][k];
		}
		fprintf(fp1, "%s", name);
		fprintf(fp1, "%s", " ");
		fprintf(fp1, "%s\n", hasharr);
		fflush(fp1);
	}
	fclose(fp1);

	return flg;
}
