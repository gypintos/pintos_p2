cd build/
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -q -f
pintos -p ../../example/echo -a echo -- -q
pintos -q run 'echo x'
