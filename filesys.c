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

// int count = 0;

struct node{
	char *hash;
	struct node *next;
	struct node *prev;
};

struct node *node_arr[1024];

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

int create_merkel_tree(const char *filepath, int fp, int sz){
	printf("%s\n", "running merkel tree");
	struct node* head = (struct node*)malloc(sizeof(struct node));
	struct node* end = (struct node*)malloc(sizeof(struct node));

	int ptr = 0;

	while(ptr < sz){

		char *data = malloc(65*sizeof(char));
		if(sz - ptr < 64){
			read(fp, data, sz - ptr);
		}else{
			read(fp, data, 64);
		}
		if(ptr == 0){
			head->hash = malloc(21);
			get_sha1_hash(data, 64, head->hash);
			head->next = NULL;
			head->prev = NULL;
			end = head;
		}else{
			struct node *temp = (struct node*)malloc(sizeof(struct node));
			temp->hash = (char *)malloc(21);
			get_sha1_hash(data, 64, temp->hash);
			end->next = temp;
			temp->prev = end;
			end = temp;
		}
		ptr += 64;
	}
	printf("%s\n", "data blocks converted to hash");
	char *final = (char *)malloc(21);
	if (sz == 0) {
		head->hash = "0";
		head->next = NULL;
		head->prev = NULL;
		end = head;
		final = "0";
	} else {
		printf("%s\n", "working till here");
		while(head != NULL){
			if(head->next == NULL){
				printf("%s\n", "breaking out of loop");
				final = head->hash;
				break;
			}
			char *a1 = head->hash;
			char *b1 = head->next->hash;
			char *a = malloc(21);
			char *b = malloc(21);
			a = strtok(a1, "\0");
			b = strtok(b1, "\0");
			if(b == NULL){
				b = a;
			}
			if(a == NULL){
				a = b;
			}
			strcat(a,b);	
			struct node *temp = (struct node*)malloc(sizeof(struct node));
			temp->hash = (char *)malloc(21);
			get_sha1_hash(a, 42, temp->hash);
			end->next = temp;
			temp->prev = end;
			end = temp;
			head = head->next->next;
		}
	}
	printf("%s\n", "before secure.txt");
	int has_file = 0;
	if (access("secure.txt", F_OK) == -1) {
		printf("%s\n", "secure.txt doesn't exist");
		FILE *fp1 = fopen("secure.txt", "w");
		fclose(fp1);
	} else {
		FILE *fp1 = fopen("secure.txt", "r");
		char *line = NULL;
		size_t len = 0;
		ssize_t read = 0;
		while ((read = getline(&line, &len, fp1)) != -1){
			char *name = strtok(line, " ");
			char *hash1 = strtok(NULL, " ");
			char *hash = strtok(hash1, "\n");
			printf("%s\n", name);
			if(!strcmp(filepath, name)){
				has_file = 1;
				if(strcmp(hash, final) != 0){
					return -1;
				}else{
					if (node_arr[fp] == NULL) {
						node_arr[fp] = (struct node *)malloc(sizeof(struct node));
					}
					node_arr[fp] = head;
				}
			}
		}

		fclose(fp1);
	}
	if (!has_file) {
		FILE *fp1 = fopen("secure.txt", "a");
		printf("%s %s\n", "writing to file", filepath);
		fprintf(fp1, "%s ", filepath);
		if (final == NULL) {
			fprintf(fp1, "%s\n", "0");
		} else {
			fprintf(fp1, "%s\n", final);
		}
		fflush(fp1);
		fclose(fp1);
	}

	return 1;
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
	FILE *fp = fopen(pathname, "r");
	int sz = 0;
	if (fp == NULL) {
		sz = 0;
	} else {
		fseek(fp, 0L, SEEK_END);
		sz = ftell(fp);
		fseek(fp, 0L, SEEK_SET);
		fclose(fp);
	}
	
	int fd = open(pathname, flags, mode);
	printf("'%s %s'\n", "pathname", pathname);
	printf("%s %d\n", "fd", fd);
	printf("%s %d\n", "size", sz);
	int filehash = create_merkel_tree(pathname, fd, sz);
	if (filehash == -1) {
		return -1;
	}
	assert (filesys_inited);
	return fd;
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
	for(int i = 0; i < 1024; i++){
		node_arr[i] = NULL;
	}
	filesys_inited = 1;
	return 0;
}
