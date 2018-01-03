#!/usr/bin/env python3

from pow.pow import *
from messages import *
from network import *
import json,time,os,_thread
class Fullnode:
    def __init__(self):
        self.prev_hash="aaa"
        self.transaction_list=[]
        self.flag_mining=True
        self.flag_restart_mining=False
        self.addr=""
        self.block_list=[]
        self.key=""

    def start_listening(self,port=10086):
        _thread.start_new_thread(init,(port,))

    def start_mining(self):
        self.flag_mining=True
        while self.flag_mining:
            gen_tr={}
            gen_tr['dst_addr']=self.addr
            gen_tr['value']=25
            gen_tr['timestamp']=int(time.time())
            self.transaction_list.insert(0,gen_tr)

            block=create_block()
            block['prev_hash']=self.prev_hash
            hash_list = hash_transaction_list(self.transaction_list)
            block['merkel_root']=merkel_hash(hash_list)

            self.flag_restart_mining = False
            print('mining')
            while self.flag_restart_mining == False:
                r = mining_once(block)
                if r is not None:
                    #send block to network

                    block_hash = save_block(r)
                    save_block_transaction_info(block_hash, hash_list)
                    block_message = BlocksMessage([block_hash,hash_list])
                    #broadcast_message(BlocksMessage)
                    self.prev_hash=block_hash
                    self.block_list.append(block_hash)
                    with open('block/head.json','w') as f:
                        json.dump([block_hash],f)
                    for tr in self.transaction_list:
                        save_transaction(tr)
                    self.transaction_list.clear()
                    break
                self.check_transaction()
                

    def restart_mining(self,block_hash):
        self.prev_hash=block_hash
        self.flag_restart_mining=True
            
    def stop_mining(self):
        self.flag_mining=False
        self.flag_restart_mining=True

    def check_transaction(self):
        try:
            os.stat('transaction/new.json')
        except:
            return            
        print('reading new transaction')
        time.sleep(1)
        with open('transaction/new.json','r') as f:
            del self.transaction_list[0]
            tr = json.load(f)
            if tr not in self.transaction_list:
                self.transaction_list.append(tr)
        os.remove('transaction/new.json')
        self.flag_restart_mining=True
        print('transaction addedd')

    def load_addr(self,file_name):
        if os.path.exists(file_name):
            with open(file_name,'r') as f:
                self.addr=json.load(f)[0]
    def load_key(self,file_name):
        if os.path.exists(file_name):
            with open(file_name,'r') as f:
                self.key=json.load(f)[0]
                self.addr=get_addr_from_sk(self.key)

    def create_transaction(self,dst_addr,value):
        if self.key == "":
            return None
        else:
            return create_transaction(self.addr,dst_addr,value,self.key)

    def load_latest_block(self):
        if os.path.exists('block/head.json'):
            with open('block/head.json','r') as f:
                self.prev_hash=json.load(f)[0]
        else:
            self.prev_hash='aaa'

    def update_block_list(self):
        self.block_list.clear()
        prev_hash=self.prev_hash
        while prev_hash != 'aaa':
            self.block_list.append(prev_hash)
            block = load_block(prev_hash)
            prev_hash = block['prev_hash']
    def get_block_list(self):
        return self.block_list
    def get_addr_value(self,addr):
        self.update_block_list()
        value = 0
        for block_hash in self.block_list:
            if block_hash != 'aaa':
                tr_hash_list = load_block_transaction_info(block_hash)
                for tr_hash in tr_hash_list:
                    tr = load_transaction(tr_hash)
                    if tr['dst_addr'] == addr:
                        value = value + tr['value']
                        #print('----> ' + str(tr['value']))
                    elif 'src_addr' in tr.keys() and tr['src_addr'] == addr:
                        value = value - tr['value']
                        #print('<---- ' + str(tr['value']))
        return value


