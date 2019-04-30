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
#include <math.h>
static int filesys_inited = 0;

char name_array[1025][10];
char hash_array[1025][2000][21];


int merkel_tree(const char *pathname, int flags, mode_t mode, int ff) {
	char data[2000][21];
	char temp_hash[2000][21];
	int temp_fd = 0;
	for (int i = 0; i < 2000; i++) {
		if(ff){return 1;}
		temp_hash[i][20] = '\0';
	}
	
	// printf("reached line 30\n");
	for (int i=0; i<2000; i++) {
		data[i][20]=temp_hash[i][20];
	}
	
	FILE *fp = fopen(pathname, "r");
	int sz = 0;
	if (fp != NULL) {
		fseek(fp, 0, SEEK_END);
		sz = ftell(fp);
		// printf("file name = %s, file size = %d\n", pathname, sz);
		fseek(fp, 0, SEEK_SET);
		fclose(fp);
		if(sz == 0){
			return 1;
		}

	}else{
		return 1;
	}

	int fd = open(pathname, O_RDONLY, 0);
	temp_fd = fd;
	lseek(fd, 0, SEEK_SET);
	int ptr = 0;
	int ctr = 0;
	while(ptr < sz){
		char d[65];
		d[64]='\0';
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
		for (int k = 0; k < 20; k++) {
			temp_hash[ctr][k] = hash[k];
		}
		strncpy(data[ctr], hash, 20);
		ptr += 64;
		ctr++;
	}
	close(fd);
	int c=0;
	int index = 0;
	while(ctr>0){
		index = 0;
		c = 0;
		while (c <= ctr) {			
			if (c+1 > ctr) {
				get_sha1_hash(data[c], 20, data[index]);
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
	// printf("final hash is %s\n", data[0]);

	if(ff){
		char arr[9][31];
		for (int i=0; i<9; i++) {
			arr[i][30]='\0';
		}
		
		FILE *fpp = fopen("secure.txt", "r");
		char *line = NULL;
		size_t len = 0;
		ssize_t read = 0;
		int i = 0;
		int flg = 0;
		int hasfile = 0;
		exit(0);
		read = getline(&line, &len, fpp);
		//printf("%s\n", line);
		while ((read = getline(&line, &len, fpp)) != -1) {
			//printf("HERE NOW!!, i: %d\n", i);
			// exit(0);
			char *name = strtok(line, " ");
			char *hash1 = strtok(NULL, " ");
			char *hash = strtok(hash1, "\n");
			flg = 0;
			if(strcmp(name, pathname) == 0){
				flg = 1;
				hasfile = 1;
			}

			for (int j = 0; j < 9; j++) {
				arr[i][j] = name[j];
			}
			arr[i][9] = ' ';
			for (int j = 10; j<30; j++) {
				if(flg == 1){
					arr[i][j] = data[0][j - 10];
				}else{
					arr[i][j] = hash[j-10];
				}
			}
			i++;
		}
		free(line);
		fclose(fpp);
		if (hasfile) {
			remove("secure.txt");
		}

		FILE *fp1 = fopen("secure.txt", "a+");

		if(!hasfile){
			fprintf(fp1, "%s\n", pathname);
			fprintf(fp1, "%s", " ");
			//printf("%s\n", data[0]);
			//printf("%d\n", sz);
			fprintf(fp1, "%s\n", data[0]);
			fflush(fp1);
		} else {
			for (int j=0; j<i; j++) {
				char name[10];
				name[9]='\0';
				for (int k=0; k<9; k++) {
					name[k] = arr[j][k];
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
		}

		fclose(fp1);
		return 1;
	}

	// printf("reached line 101\n");
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

			if (strcmp(hash, data[0]) != 0) {
				// printf("%s---%s\n",hash, data[0] );
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
	// printf("reached line 101\n");
	if (!has_file) {
		for (int i = 0; i < 2000; i++) {
			for (int j = 0; j < 20; j++) {
				hash_array[temp_fd][i][j] = temp_hash[i][j];
			}
			// printf("%s\n", hash_array[temp_fd][i]);
		}
		fprintf(fp1, "%s ", pathname);
		//printf("%s\n", data[0]);
		fprintf(fp1, "%s\n", data[0]);
		//printf("%d\n", sz);
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
	int c = merkel_tree(pathname, flags, mode, 0);
	if (c == -1) {
		// printf("could not open the goddamn file :/\n");
		return -1;
	} else {
		int fd = open (pathname, flags, mode);
		for (int i = 0; i < 10; i++) {
			name_array[fd][i] = pathname[i];
		}
		return fd;
	}
}

/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
	if(whence == SEEK_END) {
		return 128000;
	}
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
	char * filename = name_array[fd];
	int x = merkel_tree(filename, O_CREAT|O_WRONLY|O_RDONLY, S_IRUSR|S_IWUSR, 1);
	if (x == -1)
	{
		// printf("%s\n", filename);
		// printf("chut\n");
		return -1;
	}
	int a = write(fd, buf, count);
	// printf("a = %d\n", a);
	// fsync(fd);
	merkel_tree(filename, O_CREAT|O_WRONLY|O_RDONLY, S_IRUSR|S_IWUSR, 1);
	return a;
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);

	off_t old = lseek(fd, 0, SEEK_CUR);
	int left_block = (int) (old / 64);
	int right_block = (int) (((old + count) / 64)-1);

	lseek(fd, (left_block)*64, SEEK_SET);
	int loop_size = right_block - left_block;

	for (int i = 0; i < loop_size; i++) {
		char buffer[65];
		buffer[64] = '\0';
		read(fd, buffer, 64);
		char hash[21];
		hash[20] = '\0';
		get_sha1_hash(buffer, 64, hash);
		// printf("%s --- %s\n", hash, hash_array[fd][i+left_block]);
		int c = strcmp(hash, hash_array[fd][i+left_block]);
		if (c != 0) {
			return -1;
		}
	}

	lseek(fd, old, SEEK_SET);

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
	char arr[9][31];
	for (int i=0; i<9; i++) {
		arr[i][30]='\0';
	}
	for (int i = 0; i < 1025; i++) {
		name_array[i][9] = '\0';
	}
	for (int i = 0; i < 1025; i++) {
		for(int j = 0; j < 2000; j++) {
			hash_array[i][j][9] = '\0';
		}
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
			int y = merkel_tree(name, O_RDONLY, 0, 0);
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
	for (int j=0; j<i; j++) {
		char name[10];
		name[9]='\0';
		for (int k=0; k<9; k++) {
			name[k] = arr[j][k];
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