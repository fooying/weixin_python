export PYTHONPATH=/opt
ps -ef|grep 'uwsgi -s :8000'|grep -v grep |awk '{print $2} '|xargs kill -9
#ps -ef|grep "a3_api.py 80"|grep -v grep |awk '{print $2} '|xargs kill -9
#uwsgi -s :9000 -w a3_api -M -p 4 -t 30 --limit-as 128 -R 10000 -d uwsgi.log
uwsgi -s :8000 -w index -p 2 -d /mnt/log/www/uwsgi_gongji.log -M -p 4  -t 30  -R 10000 
