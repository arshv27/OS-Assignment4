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

struct node{
	char *hash;
	struct node *next;
	struct node *prev;
};

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

char* create_merkel_tree(int fp, int sz){
	
	struct node* head = (struct node*)malloc(sizeof(struct node));
	struct node* end = (struct node*)malloc(sizeof(struct node));

	int ptr = 0;
	while(ptr < sz){
		char data[64];
		if(sz - ptr < 64){
			read(fp, data, sz - ptr);
		}else{
			read(fp, data, 64);
		}
		if(ptr == 0){
			get_sha1_hash(data, 20, head->hash);
			head->next = NULL;
			head->prev = NULL;
			end = head;
		}else{
			struct node *temp = (struct node*)malloc(sizeof(struct node));
			get_sha1_hash(data, 20, temp->hash);
			end->next = temp;
			temp->prev = end;
			end = temp;
		}
		ptr += 64;
	}
	char *final;
	while(head != NULL){
		if(head->next == NULL){
			final = head->hash;
			break;
		}
		char *a = head->hash;
		char *b = head->next->hash;
		char *c = strcat(a, b);		
		struct node *temp = (struct node*)malloc(sizeof(struct node));
		get_sha1_hash(c, 20, temp->hash);
		end->next = temp;
		temp->prev = end;
		end = temp;
		head = head->next->next;
	}

	return final;
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
	fseek(fp, 0L, SEEK_END);
	int sz = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	fclose(fp);

	int fd = open(pathname, flags, mode);

	FILE *fp = fopen("secure.txt", "a+");
	
	
	assert (filesys_inited);
	return open (pathname, flags, mode);
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
	return 0;
}

int main(){
	return 0;
}
