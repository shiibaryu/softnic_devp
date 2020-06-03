#include <sys/mman.h>
#include <sys/stat.h>       
#include <fcntl.h>           
#include <string.h>
#include <sys/sem.h>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"

#include "rx_shm_port1.h"

#define RX_SHM_PATH "/rx_shm_port1"
#define RX_KEY_VAL   	500
#define RX_SHM_SIZE 	1500*248

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;

const Commands RxShmPort1::cmds = {
	{"add","EmptyArg",MODULE_CMD_FUNC(&RxShmPort1::CommandAdd),
		Command::THREAD_UNSAFE},
	{"clear","EmptyArg",MODULE_CMD_FUNC(&RxShmPort1::CommandClear),
		Command::THREAD_UNSAFE}};

union semun{
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};
union semun rx_sem1;
unsigned short set_val[1];

enum SEM_OPS{
	UNLOCK = -1,
	STOP = 0,
	LOCK = 1,
};

struct shm_conf{
	int sem_id;
	char *buf;
	unsigned short val[1];
};
struct shm_conf rx_shmc1;

CommandResponse RxShmPort1::Init(const bess::pb::EmptyArg &)
{
	int fd,ret;
	int mem_size = RX_SHM_SIZE;
	memset(&rx_shmc1,0,sizeof(rx_shmc1));

	fd = shm_open(RX_SHM_PATH,O_RDWR,0);
	if(fd == -1){
		fd = shm_open(RX_SHM_PATH, O_CREAT | O_EXCL | O_RDWR,0600);
		if(fd == -1){
			return CommandFailure(errno,"failed to shm_open()");
		}
	}

	ret = ftruncate(fd,mem_size);
	if(ret == -1){
		return CommandFailure(errno,"failed to ftruncate");
	}

	rx_shmc1.buf = (char *)mmap(NULL,mem_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
	if(rx_shmc1.buf == MAP_FAILED){
		return CommandFailure(errno,"failed to mmap for buffer");
	}

	close(fd);

	rx_shmc1.sem_id = semget(RX_KEY_VAL,1,0666 | IPC_CREAT);
	if(rx_shmc1.sem_id == -1){
		return CommandFailure(errno,"failed to acquire semaphore");
	}
	
	set_val[0] = 0;
	rx_sem1.array = set_val;
	semctl(rx_shmc1.sem_id,0,SETALL,rx_sem1);

	return CommandSuccess();
}

CommandResponse RxShmPort1::CommandAdd(const bess::pb::EmptyArg &)
{
	return CommandSuccess();
}

CommandResponse RxShmPort1::CommandClear(const bess::pb::EmptyArg &)
{
	if(munmap(rx_shmc1.buf,RX_SHM_SIZE) == -1){
		LOG(INFO) << "failed to shm unmap";
	}

	if(shm_unlink(RX_SHM_PATH) == -1){
		LOG(INFO) << "failed to unlink shm";
	}

	auto result = semctl(rx_shmc1.sem_id,0,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}
	return CommandSuccess();
}

void RxShmPort1::WritePkt(bess::PacketBatch *batch)
{
	int i,cnt,pktlen;
	char *data;
	bess::Packet *pkt;
	char *shm = rx_shmc1.buf;

	cnt = batch->cnt();
	for(i=0;i<cnt;i++){
		//just wait
		while(semctl(rx_shmc1.sem_id,0,GETVAL,rx_sem1) != 0){}
		pkt = batch->pkts()[i];
		pktlen = pkt->total_len();
		data = pkt->head_data<char *>();
		memcpy(shm,data,pktlen);
		LOG(INFO) << "rx done: write pkt to shm";
		shm+= 1500;
	}
	set_val[0] = cnt;
	rx_sem1.array = set_val;
	semctl(rx_shmc1.sem_id,0,SETALL,rx_sem1);
}

void RxShmPort1::ProcessBatch(Context *ctx, bess::PacketBatch *batch)
{
	WritePkt(batch);
	if(ctx){}
}

ADD_MODULE(RxShmPort1,"rx_shm_port1","communication port for shared memory")
