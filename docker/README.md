# build

```
docker build -t sysrepo/snabb -f Dockerfile .
docker build -t sysrepo/snabb:devel -f Dockerfile.devel .
```

# run

For loading the `ietf-softwire-v2` and `ietf-softwire-v3` yang models add `--build-arg yangmodel="ietf-softwire"`.

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
