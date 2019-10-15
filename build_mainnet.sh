contract='m'

eosio-cpp  -contract=${contract} -abigen ./src/${contract}.cpp -o ${contract}.wasm -D=MAINNET=1 -I=./include