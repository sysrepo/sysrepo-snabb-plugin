# build

```
docker build -t sysrepo/snabb -f Dockerfile .
docker build -t sysrepo/snabb:devel -f Dockerfile.devel .
```

# run

For loading the `snabb-softwire-v2` or `snabb-softwire-v3` yang models add either `--build-arg yangmodel="snabb-softwire-v2"` or `--build-arg yangmodel="snabb-softwire-v3"`.

```
sudo docker run -d -v /opt/yang:/opt/fork -v /sys/fs/cgroup:/sys/fs/cgroup:ro --cap-add SYS_ADMIN -p 830:830 --name snabb --rm --privileged --entrypoint=/sbin/init sysrepo/snabb
sudo docker run -d -v /opt/yang:/opt/fork -v /sys/fs/cgroup:/sys/fs/cgroup:ro --cap-add SYS_ADMIN -p 830:830 --name snabb --rm --privileged --entrypoint=/sbin/init sysrepo/snabb:devel
```



## enter shell

```
docker exec -i -t snabb bash
```

## close docker

```
docker stop snabb
```
