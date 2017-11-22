# Docker Machine Driver for KDDI Cloud Platform Service

[Docker Machine](https://docs.docker.com/machine/)をKCPSでも利用できるようにするドライバです。

## 実行方法

```bash:コマンド実行例
docker-machine create -d kcps --kcps-api-key [KCPS API KEY] \
		    --kcps-secret-key [KCPS SECRET KEY] \
		    --kcps-api-url [KCPS API ENDPOINT URL] \
		    --kcps-template [KCPS Template] \
		    --kcps-zone [KCPS ZONE] \
		    --kcps-zone [KCPS ZONE] \
		    [INSTANCE NAME]
```
オプション:

- `--kcps-api-key`:kcps API key
- `--kcps-api-url`:kcps API URL
- `--kcps-ingress-cidr`:SSH, dockerクライアントが接続を許可するIPレンジを指定. オプション例'xxx.xxx.xxx.xxx/xx'. デフォルト値はdocker-machineを実行するマシンのGlobalIP.
- `--kcps-network`:インスタンスにアタッチするネットワーク名.デフォルト値はPublicFrontSegment
- `--kcps-secret-key`:kcps API secret key [$KCPS_SECRET_KEY]
- `--kcps-service-offering`:kcps service offering 名. デフォルト値はMedium2(2vCPU,Mem8GB)
- `--kcps-ssh-port`:SSH port. デフォルト値は22
- `--kcps-ssh-user`:SSH user. デフォルト値はubuntu
- `--kcps-template`:kcps virtual machine template名 
- `--kcps-zone`:kcps zone name [$KCPS_ZONE]
