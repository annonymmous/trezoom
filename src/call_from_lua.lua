local call_from_lua = {}



function call_from_lua.init()
    set_my_text("Hierachical deterministic wallets as native Lua modules!")
    create_master_privkey()
    create_master_privkey_mp()
    get_coin_address("mote")
    get_coin_address("ethereum")
    get_coin_address("bitcoin")
    get_mnemonic("110155030405060708770a0b0c044e0f000102030405066708090a0b0c000e0f")
    hdnode2 = lua_hdnode_from_xprv(0, 0, "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", "secp256k1")
    print(hdnode2.curve_info)
    print(hdnode2.chain_code)
    print(hdnode2.private_key)
    print(hdnode2.private_key_extension_hex)
    print(hdnode2.public_key_hex)
    print(hdnode2.child_num)
    print(hdnode2.depth)
    hdnode3 = lua_hdnode_from_seed("000102030405060708090a0b0c0d0e0f", 16, "secp256k1")
    print(hdnode3.curve_info)
    print(hdnode3.chain_code)
    print(hdnode3.private_key_hex)
    print(hdnode3.private_key_extension)
    print(hdnode3.public_key_hex)
    print(hdnode3.child_num)
    print(hdnode3.depth)
    print("")
    print("")
    hdnode4 = lua_hdnode_fingerprint(
        0,
        0,
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        "",
        "0339A36013301597DAEF41FBE593A02CC513D0B55527EC2DF1050E2E8FF49C85C2",
        "secp256k1",
        3
    )
    print(hdnode4.fingerprint)
    
end



return call_from_lua

--  cc *.c ed25519-donna/*.c -o call_from_lua -llua -L../lua -I../lua  -L./ed25519-donna -I../src -v 