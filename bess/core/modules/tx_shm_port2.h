#ifndef BESS_MODULES_SHMPORT_H_
#define BESS_MODULES_SHMPORT_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/syscallthread.h"

#define MAX_TEMPLATE_SIZE 1000

class TxShmPort2;

class TxShmPortThread2 final : public bess::utils::SyscallThreadPfuncs, public Module{
	public:
		TxShmPortThread2(TxShmPort2 *owner) : owner_(owner) {}
		void Run() override;
		
	private:
		TxShmPort2 *owner_;
};

class TxShmPort2 final : public Module{
	public:
		TxShmPort2()
		  : shm_thread_(this){}
		    //templ_(){}

		void DeInit() override;

		static const Commands cmds;

		struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg)override;
		
		CommandResponse Init(const bess::pb::EmptyArg &);
		CommandResponse CommandAdd(const bess::pb::EmptyArg &arg);
		CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

	private:
		void FillPacket(bess::Packet *p,struct tx_shmq *txsq);
		void GeneratePackets(Context *ctx, bess::PacketBatch *batch,bess::Packet *p,struct tx_shmq *txsq);

		friend class TxShmPortThread2;
		TxShmPortThread2 shm_thread_;

		int template_size_;

};

#endif 
