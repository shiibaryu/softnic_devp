#include <sys/mman.h>
#include <sys/stat.h>       
#include <fcntl.h>           
#include <string.h>
#include <sys/sem.h>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"

#include "nettlp_shm.h"
#include "rx_shm_port3.h"

#define RX_SHM_PATH "/rx_shm_port3"
#define RX_KEY_VAL   	700
#define RX_SHM_SIZE 	1500*248

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;

const Commands RxShmPort3::cmds = {
	{"add","EmptyArg",MODULE_CMD_FUNC(&RxShmPort3::CommandAdd),
		Command::THREAD_UNSAFE},
	{"clear","EmptyArg",MODULE_CMD_FUNC(&RxShmPort3::CommandClear),
		Command::THREAD_UNSAFE}};

union semun{
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *_buf;
};
union semun rx_sem3;
unsigned short set_val3[1];

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
struct shm_conf rx_shmc3;

CommandResponse RxShmPort3::Init(const bess::pb::EmptyArg &)
{
	int fd,ret;
	int mem_size = RX_SHM_SIZE;
	memset(&rx_shmc3,0,sizeof(rx_shmc3));

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

	rx_shmc3.buf = (char *)mmap(NULL,mem_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
	if(rx_shmc3.buf == MAP_FAILED){
		return CommandFailure(errno,"failed to mmap for buffer");
	}

	close(fd);

	rx_shmc3.sem_id = semget(RX_KEY_VAL,1,0666 | IPC_CREAT);
	LOG(INFO) << "sem id 3 " << rx_shmc3.sem_id;
	if(rx_shmc3.sem_id == -1){
		return CommandFailure(errno,"failed to acquire semaphore");
	}
	
	set_val3[0] = 0;
	rx_sem3.array = set_val3;
	semctl(rx_shmc3.sem_id,0,SETALL,rx_sem3);

	return CommandSuccess();
}

CommandResponse RxShmPort3::CommandAdd(const bess::pb::EmptyArg &)
{
	return CommandSuccess();
}

CommandResponse RxShmPort3::CommandClear(const bess::pb::EmptyArg &)
{
	if(munmap(rx_shmc3.buf,RX_SHM_SIZE) == -1){
		LOG(INFO) << "failed to shm unmap";
	}

	if(shm_unlink(RX_SHM_PATH) == -1){
		LOG(INFO) << "failed to unlink shm";
	}

	auto result = semctl(rx_shmc3.sem_id,0,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}
	return CommandSuccess();
}

char *shm3 = rx_shmc3.buf;
void RxShmPort3::WritePkt(bess::PacketBatch *batch)
{
	int i,cnt,pktlen;
	//char *data;
	bess::Packet *pkt;
	struct rx_shmq rxsq;

	pktlen = 0;

	cnt = batch->cnt();
	for(i=0;i<cnt;i++){
		//just wait
		while(semctl(rx_shmc3.sem_id,0,GETVAL,rx_sem3) != 0){}
		LOG(INFO) << "finish waiting";
		pkt = batch->pkts()[i];
		pktlen = pkt->data_len();
		if(pktlen > 0){
			rxsq.length = pktlen;
			LOG(INFO) << "pktlen " << pktlen;
			//data = pkt->head_data<char *>();
			memcpy(rxsq.data,pkt->head_data(),pktlen);
			memcpy(rx_shmc3.buf,&rxsq,sizeof(struct rx_shmq));
			LOG(INFO) << "rx done: write pkt to shm";
			shm3 += sizeof(rxsq);
		}
	}
	if(cnt && pktlen > 0){
		set_val3[0] = cnt;
		rx_sem3.array = set_val3;
		LOG(INFO) << "semavl is " << cnt;
		if(semctl(rx_shmc3.sem_id,0,SETALL,rx_sem3)==-1){
			LOG(INFO) << "errrrrr";
		}
	}

}

void RxShmPort3::ProcessBatch(Context *ctx, bess::PacketBatch *batch)
{
	if(batch->cnt() > 0){
		WritePkt(batch);
		LOG(INFO) << "process batch";
	}
	if(ctx){}
}

ADD_MODULE(RxShmPort3,"rx_shm_port3","communication port for shared memory")
