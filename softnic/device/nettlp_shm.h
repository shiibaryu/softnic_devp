#ifndef _NETTLP_SHM_H_
#define _NETTLP_SHM_H_

#define TX1_SHM_PATH	"/tx1_shm"
#define TX2_SHM_PATH	"/tx2_shm"
#define TX3_SHM_PATH	"/tx3_shm"
#define TX4_SHM_PATH	"/tx4_shm"
#define RX1_SHM_PATH	"/rx1_shm"
#define RX2_SHM_PATH	"/rx2_shm"
#define RX3_SHM_PATH	"/rx3_shm"
#define RX4_SHM_PATH	"/rx4_shm"

#define SHM_SIZE	2048*256  //MAX_PACKET_SIZE*NUM_OF_DESCRIPTOR
#define TX_SHM_DESC_SIZE	sizeof(struct tx_shm_desc)*256 
#define RX_SHM_DESC_SIZE	sizeof(struct rx_shm_desc)*256 

struct tx_shmq{
	uint32_t length;
	char data[4096];
}__attribute__((packed));

struct rx_shmq{
	uint32_t length;
	char data[4096];
}__attribute__((packed));

#endif
