#ifndef BESS_MODULES_SHM_H_
#define BESS_MODULES_SHM_H_

#define MAX_PKT_NUM	10
#define DESC_ENTRY_SIZE   256

struct tx_shm_conf{
	int sem_id;
	char *buf;
	char *current;
	int idx;
	unsigned short val[1];
};

struct tx_shmq{
	uint32_t length;
	char data[4096];
}__attribute__((packed));

struct rx_shmq{
	uint32_t length;
	char data[4096];
}__attribute__((packed));

#endif
