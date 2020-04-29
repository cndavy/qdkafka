keytool -genkeypair -alias serverkey -keyalg RSA -keysize 2048 -validity 3650 -keystore tomatocc.keystore

storepass keystore 文件存储密码
keypass 私钥加解密密码
alias 实体别名(包括证书私钥)
dname 证书个人信息
keyalt 采用公钥算法，默认是DSA
keysize 密钥长度(DSA算法对应的默认算法是sha1withDSA，不支持2048长度，此时需指定RSA)
validity 有效期
keystore 指定keystore文件
 
 keytool -v -list -keystore tomatocc.keystore
 
 keytool -exportcert -keystore tomatocc.keystore -file tomatocc.cer -alias serverkey
 
 keytool -importkeystore -srckeystore tomatocc.keystore -destkeystore tomatocc.p12 -srcalias serverkey -destalias serverkey -srcstoretype jks -deststoretype pkcs12 -noprompt
 ————————————————
 
 