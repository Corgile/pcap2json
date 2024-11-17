STRING(ASCII 27 ESC)
SET(RST "${ESC}[0m")

SET(BLK "${RST}${ESC}[30m")     # 黑色
SET(RED "${RST}${ESC}[31m")     # 红色
SET(GRN "${RST}${ESC}[32m")     # 绿色
SET(YLW "${RST}${ESC}[33m")     # 黄色
SET(BLU "${RST}${ESC}[34m")     # 蓝色
SET(PRP "${RST}${ESC}[35m")     # 紫色
SET(CYN "${RST}${ESC}[36m")     # 青色
SET(WHT "${RST}${ESC}[37m")     # 白色
SET(BLKB "${RST}${ESC}[1;30m")  # 黑色（加亮）
SET(REDB "${RST}${ESC}[1;31m")  # 红色（加亮）
SET(GRNB "${RST}${ESC}[1;32m")  # 绿色（加亮）
SET(YLWB "${RST}${ESC}[1;33m")  # 黄色（加亮）
SET(BLUB "${RST}${ESC}[1;34m")  # 蓝色（加亮）
SET(PRPB "${RST}${ESC}[1;35m")  # 紫色（加亮）
SET(CYNB "${RST}${ESC}[1;36m")  # 青色（加亮）
SET(WHTB "${RST}${ESC}[1;37m")  # 白色（加亮）

SET(A "${ESC}[1m") # 设置高亮度（加粗）
SET(D "${ESC}[2m") # 设置低亮度
SET(U "${ESC}[4m") # 下划线
SET(S "${ESC}[5m") # 闪烁
SET(R "${ESC}[7m") # 反显
SET(H "${ESC}[8m") # 消隐
SET(D "${ESC}[9m") # 划掉
