#pragma once

#include <atomic>
#include <mutex>
#include <vector>
#include "utils.hpp"
#include "transforms.hpp"


// HEIGHT | VALUE > stdout
template <typename Block>
struct dumpOutputValuesOverHeight : public TransformBase<Block> {
	void operator() (const Block& block) {
		uint32_t height = 0xffffffff;
		if (this->shouldSkip(block, nullptr, &height)) return;

		std::array<uint8_t, 12> buffer;
		serial::place<uint32_t>(buffer, height);

		auto transactions = block.transactions();
		while (not transactions.empty()) {
			const auto& transaction = transactions.front();

			for (const auto& output : transaction.outputs) {
				serial::place<uint64_t>(range(buffer).drop(4), output.value);
				fwrite(buffer.begin(), buffer.size(), 1, stdout);
			}

			transactions.popFront();
		}
	}
};


// HEIGHT | BLOCK_TOTAL_VALUES > stdout
template <typename Block>
struct dumpBlockValue : public TransformBase<Block> {
	uint32_t max_blocks;
	dumpBlockValue() { max_blocks = 0;}

	void dump_one_output(uint256_t &tx_hash, address_t &address, uint64_t value, int dump_ascii = 0, int skip = 0){
		std::array<uint8_t, 1024> buffer;
		if(skip) return;
		auto res = range(buffer);
		// DUMP - ASCII
		if (dump_ascii){
			res.put(zstr_range(toHexBE(tx_hash).c_str()));
			serial::put<char>(res, '\n');
			// res.put(zstr_range(toHex(address).c_str()));
			// serial::put<char>(res, '\n');
			std::string str = base58encode(address);
			res.put(zstr_range(str.c_str()));
			serial::put<char>(res, '\n');
		}else{
		// DUMP - BINDATA
			serial::put<uint64_t>(res, value);
			res.put(range(tx_hash));
			res.put(range(address));
		}
		fwrite(buffer.begin(), buffer.size() - res.size(), 1, stdout);
	}
	// FIXED ME, NEED CHECK(m <= n)
	int is_p2pkh_multisig(const uint8_t *s, const size_t len){
		int ret = 0;
		if(OP_1 <= s[0] && s[0] <= OP_16 && OP_1 <= s[len-2] && s[len-2] <= OP_16 && s[len-1] == OP_CHECKMULTISIG){
			int M = s[0], N = s[len-2];
			if (M <= N){
				ret = 1;
			}
		}
		return ret;
	}
	void operator() (const Block& block) {
		// std::array<uint8_t, 4096> buffer;
		uint32_t height = 0xffffffff;
		uint64_t sum = 0;
		// if (this->max_blocks++ >= 1) return;
		if (this->shouldSkip(block, nullptr, &height)) return;
		auto transactions = block.transactions();

		while (not transactions.empty()) {
			const auto& transaction = transactions.front();
			auto tx_hash = transaction.hash();
			for (const auto& output : transaction.outputs) {
				sum += output.value;
				auto s = range(output.script);
				uint8_t *spt = s.data();
				size_t spt_len = s.size();
				if(spt[0] == OP_PUSHDATA_N(65) && spt[spt_len-1] == OP_CHECKSIG && spt_len == 67){
					auto pk = range(output.script);
					pk.popFrontN(1);
					pk.popBackN(1);
					auto address = pubkey2address(pk);
					this->dump_one_output(tx_hash, address, output.value);
				}else if(spt[0] == OP_PUSHDATA_N(33) && spt[spt_len-1] == OP_CHECKSIG && spt_len == 35){
					auto pk = range(output.script);
					pk.popFrontN(1);
					pk.popBackN(1);
					auto address = pubkey2address(pk);
					this->dump_one_output(tx_hash, address, output.value);
				}else if(spt[0] == OP_DUP && spt[1] == OP_HASH160 && spt[2] == OP_PUSHDATA_N(20) && spt[spt_len-2] == OP_EQUALVERIFY && spt[spt_len-1] == OP_CHECKSIG && spt_len == 25){
					auto hash = range(output.script);
					hash.popFrontN(3);
					hash.popBackN(2);
					uint160_t h160;
					std::copy(hash.begin(), hash.end(), h160.begin());
					auto address = hash2address(h160, 0);
					this->dump_one_output(tx_hash, address, output.value);
					// std::array<uint8_t, 256> buffer;
					// auto res = range(buffer);
					// res.put(zstr_range(toHex(hash).c_str()));
					// serial::put<char>(res, '\n');
					// fwrite(buffer.begin(), buffer.size() - res.size(), 1, stdout);
				}else if(spt[0] == OP_HASH160 && spt[1] == OP_PUSHDATA_N(20) && spt[spt_len-1] == OP_EQUAL && spt_len == 23){
					auto hash = range(output.script);
					hash.popFrontN(2);
					hash.popBackN(1);
					uint160_t h160;
					std::copy(hash.begin(), hash.end(), h160.begin());
					auto address = hash2address(h160, 5);
					this->dump_one_output(tx_hash, address, output.value);
				}else if(is_p2pkh_multisig(spt, spt_len)){
					auto save = range(output.script);
					auto opcM = serial::read<uint8_t>(save);
					while (not save.empty()) {
						const auto opcode = serial::read<uint8_t>(save);
						if ((opcode > OP_0) && (opcode <= OP_PUSHDATA4)) {
							const auto dataLength = readPD(opcode, save);
							assert(dataLength > save.size());
							const auto pk = save.take(dataLength);
							save.popFrontN(dataLength);
							auto address = pubkey2address(pk);
							this->dump_one_output(tx_hash, address, output.value);
						}else if(OP_1 <= opcode && opcode <= OP_16){
							const auto opcEND = serial::read<uint8_t>(save);
							assert(opcEND == OP_CHECKMULTISIG);
							// std::cout <<"parse successful ..."<< std::endl;
							break;
						}
					}
				}
			}
			transactions.popFront();
		}
		// std::cout <<"Block height: " << height << ", total_value: " << sum << std::endl;
	}
};


template <typename Block>
struct dumpTxOutputsInfo : public TransformBase<Block> {
	std::atomic_ulong outputs;
	std::atomic_ulong p2pk_count;
	std::atomic_ulong p2pkh_count;
	std::atomic_ulong p2pkz_count;
	std::atomic_ulong p2sh_count;
	std::atomic_ulong p2pkh_multisig_count;
	std::atomic_ulong unk_count;
	dumpTxOutputsInfo() {
		this->outputs = 0;
		this->p2pk_count = 0;
		this->p2pkh_count = 0;
		this->p2pkz_count = 0;
		this->p2sh_count = 0;
		this->p2pkh_multisig_count = 0;
		this->unk_count = 0;
	}
	virtual ~dumpTxOutputsInfo() {
		std::cerr <<
			"outputs:\t" << this->outputs << '\n' <<
			"p2pk_count:\t" << this->p2pk_count << '\n' <<
			"p2pkz_count:\t" << this->p2pkz_count << '\n' <<
			"p2pkh_count:\t" << this->p2pkh_count << '\n' <<
			"p2sh_count:\t" << this->p2sh_count << '\n' <<
			"p2pkh_multisig_count:\t" << this->p2pkh_multisig_count << '\n' <<
			"unk_count:\t" << this->unk_count << '\n' <<
			std::endl;
	}
	int is_p2pkh_multisig(const unsigned char *s, const size_t len){
		int ret = 0;
		if(OP_1 <= s[0] && s[0] <= OP_16 && s[len-1] == OP_CHECKMULTISIG){
			// FIXED ME, NEED CHECK(m <= n)
			ret = 1;
		}
		return ret;
	}

	void operator() (const Block& block) {
		std::array<uint8_t, 4096> buffer;
		uint32_t height = 0xffffffff;
		if (this->shouldSkip(block, nullptr, &height)) return;

		auto transactions = block.transactions();
		while (not transactions.empty()) {
			const auto& transaction = transactions.front();
			for (const auto& output : transaction.outputs) {
				auto s = range(output.script);
				auto res = range(buffer);
				uint8_t *script = s.data();
				size_t script_len = s.size();
				this->outputs++;
				if(script[0] == OP_PUSHDATA_N(65) && script[script_len-1] == OP_CHECKSIG && script_len == 67){
					this->p2pk_count++;
					if (this->p2pk_count == 1){
						auto hash = transaction.hash();
						res.put(zstr_range(toHexBE(hash).c_str()));
						serial::put<char>(res, '\n');
					}
					// res.put(zstr_range("P2PK\n"));
				}else if(script[0] == OP_PUSHDATA_N(33) && script[script_len-1] == OP_CHECKSIG && script_len == 35){
					this->p2pkz_count++;
					// res.put(zstr_range("P2PKZ\n"));
				}else if(script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == OP_PUSHDATA_N(20) && script[script_len-2] == OP_EQUALVERIFY && script[script_len-1] == OP_CHECKSIG && script_len == 25){
					this->p2pkh_count++;
					// res.put(zstr_range("P2PKH\n"));
				}else if(script[0] == OP_HASH160 && script[1] == OP_PUSHDATA_N(20) && script[script_len-1] == OP_EQUAL && script_len == 23){
					this->p2sh_count++;
					// res.put(zstr_range("P2SH\n"));
				}else if(is_p2pkh_multisig(script, script_len)){
					this->p2pkh_multisig_count++;
					// res.put(zstr_range("P2PKH_MULTISIG\n"));
				}else{
					this->unk_count++;
					auto hash = transaction.hash();
					res.put(zstr_range(toHexBE(hash).c_str()));
					serial::put<char>(res, '\n');
					// res.put(zstr_range("UNKNOWN-TX\n"));
				}
				auto lineLength = buffer.size() - res.size();
				if (lineLength > 0)
					fwrite(buffer.begin(), lineLength, 1, stdout);
			}
			transactions.popFront();
		}
	}
};

auto perc (uint64_t a, uint64_t ab) {
	return static_cast<double>(a) / static_cast<double>(ab);
}

template <typename Block>
struct dumpStatistics : public TransformBase<Block> {
	std::atomic_ulong inputs;
	std::atomic_ulong outputs;
	std::atomic_ulong transactions;
	std::atomic_ulong version1;
	std::atomic_ulong version2;
	std::atomic_ulong locktimesGt0;
	std::atomic_ulong nonFinalSequences;

	dumpStatistics () {
		this->inputs = 0;
		this->outputs = 0;
		this->transactions = 0;
		this->version1 = 0;
		this->version2 = 0;
		this->locktimesGt0 = 0;
		this->nonFinalSequences = 0;
	}

	virtual ~dumpStatistics () {
		std::cout <<
			"Transactions:\t" << this->transactions << '\n' <<
			"-- Inputs:\t" << this->inputs << " (ratio " << perc(this->inputs, this->transactions) << ") \n" <<
			"-- Outputs:\t" << this->outputs << " (ratio " << perc(this->outputs, this->transactions) << ") \n" <<
			"-- Version1:\t" << this->version1 << " (" << perc(this->version1, this->transactions) * 100 << "%) \n" <<
			"-- Version2:\t" << this->version2 << " (" << perc(this->version2, this->transactions) * 100 << "%) \n" <<
			"-- Locktimes (>0):\t" << this->locktimesGt0 << " (" << perc(this->locktimesGt0, this->transactions) * 100 << "%) \n" <<
			"-- Sequences (!= FINAL):\t" << this->nonFinalSequences << " (" << perc(this->nonFinalSequences, this->inputs) * 100 << "%) \n" <<
			std::endl;
	}

	void operator() (const Block& block) {
		if (this->shouldSkip(block)) return;

		auto transactions = block.transactions();
		this->transactions += transactions.size();

		while (not transactions.empty()) {
			const auto& transaction = transactions.front();

			this->inputs += transaction.inputs.size();

			size_t nfs = 0;
			for (const auto& input : transaction.inputs) {
				if (input.sequence != 0xffffffff) nfs++;
			}

			this->nonFinalSequences += nfs;
			this->outputs += transaction.outputs.size();

			this->version1 += transaction.version == 1;
			this->version2 += transaction.version == 2;
			this->locktimesGt0 += transaction.locktime > 0;

			transactions.popFront();
		}
	}
};

// ASM > stdout
template <typename Block>
struct dumpASM : public TransformBase<Block> {
	// FIXED: segmentation fault
	std::array<uint8_t, 1024*1024> buffer;
	void operator() (const Block& block) {
		if (this->shouldSkip(block)) return;

		auto transactions = block.transactions();
		while (not transactions.empty()) {
			const auto& transaction = transactions.front();
			for (const auto& output : transaction.outputs) {
				auto tmp = range(buffer);
				putASM(tmp, output.script);
				serial::put<char>(tmp, '\n');
				const auto lineLength = buffer.size() - tmp.size();

				// FIXME: stdout is non-atomic past 4096
				if (lineLength > 4096) continue;

				fwrite(buffer.begin(), lineLength, 1, stdout);
			}

			transactions.popFront();
		}
	}
};

// BLOCK_HEADER > stdout
template <typename Block>
struct dumpHeaders : public TransformBase<Block> {
	void operator() (const Block& block) {
		if (this->shouldSkip(block)) return;

		fwrite(block.header.begin(), 80, 1, stdout);
	}
};

// SCRIPT_LENGTH | SCRIPT > stdout
template <typename Block>
struct dumpScripts : public TransformBase<Block> {
	void operator() (const Block& block) {
		if (this->shouldSkip(block)) return;

		std::array<uint8_t, 4096> buffer;
		const auto maxScriptLength = buffer.size() - sizeof(uint16_t);

		auto transactions = block.transactions();
		while (not transactions.empty()) {
			const auto& transaction = transactions.front();

			for (const auto& input : transaction.inputs) {
				if (input.script.size() > maxScriptLength) continue;

				auto r = range(buffer);
				serial::put<uint16_t>(r, static_cast<uint16_t>(input.script.size()));
				r.put(input.script);
				fwrite(buffer.begin(), buffer.size() - r.size(), 1, stdout);
			}

			for (const auto& output : transaction.outputs) {
				if (output.script.size() > maxScriptLength) continue;

				auto r = range(buffer);
				serial::put<uint16_t>(r, static_cast<uint16_t>(output.script.size()));
				r.put(output.script);
				fwrite(buffer.begin(), buffer.size() - r.size(), 1, stdout);
			}

			transactions.popFront();
		}
	}
};

typedef std::pair<std::vector<uint8_t>, uint64_t> TxoDetail;
typedef std::pair<uint256_t, uint32_t> Txin;
typedef std::pair<Txin, TxoDetail> Txo;

// HEIGHT | VALUE > stdout
template <typename Block>
struct dumpUnspents : public TransformBase<Block> {
	static constexpr auto BLANK_TXIN = Txin{ {}, 0 };

	std::mutex mutex;
	HList<Txin, TxoDetail> unspents;

	void operator() (const Block& block) {
		if (this->shouldSkip(block)) return;

		std::vector<Txin> txins;
		std::vector<Txo> txos;

		auto transactions = block.transactions();
		while (not transactions.empty()) {
			const auto& transaction = transactions.front();
			const auto txHash = transaction.hash();

			for (const auto& input : transaction.inputs) {
				uint256_t prevTxHash;
				std::copy(input.hash.begin(), input.hash.end(), prevTxHash.begin());

				txins.emplace_back(Txin{prevTxHash, input.vout});
			}

			uint32_t vout = 0;
			for (const auto& output : transaction.outputs) {
				std::vector<uint8_t> script;
				script.resize(output.script.size());
				std::copy(output.script.begin(), output.script.end(), script.begin());

				txos.emplace_back(Txo({txHash, vout}, {script, output.value}));
				++vout;
			}

			transactions.popFront();
		}

		std::lock_guard<std::mutex>(this->mutex);
		for (const auto& txo : txos) {
			this->unspents.insort(txo.first, txo.second);
		}

		for (const auto& txin : txins) {
			const auto iter = this->unspents.find(txin);
			if (iter == this->unspents.end()) continue; // uh, maybe you are only doing part of the blockchain!

			iter->first = BLANK_TXIN;
		}

		this->unspents.erase(std::remove_if(
			this->unspents.begin(),
			this->unspents.end(),
			[](const auto& x) {
				return x.first == BLANK_TXIN;
			}
		), this->unspents.end());

		std::cout << this->unspents.size() << std::endl;
	}
};
