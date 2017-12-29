#!/usr/bin/eny python3
import hashlib,ecdsa,json,random,string

def get_newkey():
    return bytes.hex(ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string())

def get_pubkey(pri_key):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(pri_key),curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return bytes.hex(vk.to_string())

def get_addr_from_sk(pri_key):
    return hashlib.sha256(get_pubkey(pri_key).encode('ascii','ignore')).hexdigest()

def get_addr_from_vk(pub_key):
    return hashlib.sha256(pub_key.encode('ascii','ignore')).hexdigest()

def create_block():
    nb = {}
    nb['prev_hash']=''
    nb['nonce']=''
    nb['merkel_root']=''
    return nb

def get_latest_block_hash():
    ''' get this from local or network?'''
    return 0

def get_transaction_list():
    ''' get this from local or network?'''
    return []
    
def hash_transcation_list(tr_list):
    hash_list=[]
    for tr in tr_list:
        hash_list.append(hashlib.sha256(json.dumps(tr).encode('ascii','ignore')).hexdigest())
    return hash_list
def merkel_hash(hash_list):
    if len(hash_list) == 1:
        return hash_list[0]
    elif len(hash_list)%2 == 1:
        hash_list.append(hash_list[-1])
    new_hash_list=[]
    for i in range(int(len(hash_list)/2)):
        new_hash_list.append(hashlib.sha256((hash_list[i*2]+hash_list[i*2+1]).encode('ascii','ignore')).hexdigest())
    return merkel_hash(new_hash_list) 

def create_transcation(src_addr,dst_addr, value, key):
    tr={};
    tr['src_addr']=src_addr
    tr['dst_addr']=dst_addr
    tr['value']=value
    tr_hash=hashlib.sha256(json.dumps(tr).encode('ascii','ignore')).hexdigest()
    tr['pubkey']=get_pubkey(key)
    tr['sig']=bytes.hex(ecdsa.SigningKey.from_string(bytes.fromhex(key),curve=ecdsa.SECP256k1).sign(tr_hash.encode('ascii','ignore')))
    return tr

def verify_transcation(tr, pubkey):
    ttr={}
    ttr['src_addr']=tr['src_addr']
    ttr['dst_addr']=tr['dst_addr']
    ttr['value']=tr['value']
    tr_hash=hashlib.sha256(json.dumps(ttr).encode('ascii','ignore')).hexdigest()
    sig=bytes.fromhex(tr['sig'])
    vk=ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey), curve=ecdsa.SECP256k1)
    return vk.verify(sig, tr_hash.encode('ascii','ignore'))

   
def mining_once(block):
    block['nonce']=''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(9))

    h = hashlib.sha256(json.dumps(block).encode('ascii','ignore')).hexdigest()
    if h.startswith('00000'):
        print('try ' + block['nonce'] + ' with ' + h + ' found it!')
        return block
    else:
        return None
    
def save_block(block):
    hash_str=hashlib.sha256(json.dumps(block).encode('ascii','ignore')).hexdigest()
    with open('block/'+hash_str+'.json','w') as f:
        json.dump(block,f)
    return hash_str

def load_block(hash_str):
    with open('block/'+hash_str+'.json','r') as f:
        return json.load(f)

def save_transcation(tr):
    hash_str=hashlib.sha256(json.dumps(tr).encode('ascii','ignore')).hexdigest()
    with open('transcation/'+hash_str+'.json','w') as f:
        json.dump(tr,f)
    return hash_str

def load_transcation(hash_str):
    with open('transcation/'+hash_str+'.json','r') as f:
        return json.load(f)

def test():
    pri_key = get_newkey()
    pub_key = get_pubkey(pri_key)
    addr = get_addr_from_sk(pri_key)
    if addr == get_addr_from_vk(pub_key):
        print('key generate pass')
    tr = create_transcation('aaa','bbb',3,pri_key)
    h = save_transcation(tr)
    tr = load_transcation(h)
    if verify_transcation(tr, pub_key):
        print('transcation pass')

    cur_block = create_block()
    genration_tr={}
    genration_tr['dst_add']='aaa'
    genration_tr['value']=25
    trans_list=[genration_tr, tr]
    hash_list = hash_transcation_list(trans_list)
    cur_block['prev_hash']=hashlib.sha256(b'test').hexdigest()
    cur_block['merkel_root']=merkel_hash(hash_list)
    print('test mining')
    while True:
        r = mining_once(cur_block)
        if r is not None:
            cur_block=r
            break
    h = save_block(cur_block)
    load_block(h)

if __name__ == '__main__':
    test()
