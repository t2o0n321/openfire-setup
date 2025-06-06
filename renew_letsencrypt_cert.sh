#!/bin/bash

# --------------------------------------------------
# 解析參數
# --------------------------------------------------
# 如果沒有提供參數，則顯示錯誤訊息
if [ $# -eq 0 ]; then
  echo
  echo "Error: No domain provided."
  echo "Usage: $(basename $0) your_domain"
  echo
  exit 1
fi

domain=$1
cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
RENEW_THRESHOLD=7

# 檢查是否快過期（7 天內）
expiry_date=$(openssl x509 -enddate -noout -in "$cert_path" | cut -d= -f2)
expiry_seconds=$(date -d "$expiry_date" +%s)
now_seconds=$(date +%s)
days_left=$(( (expiry_seconds - now_seconds) / 86400 ))

if (( days_left > RENEW_THRESHOLD )); then
    echo "The certificate for $domain will expire in $days_left days, no need to renew"
    exit 0
fi

# # renew SSL 憑證
echo "Renewing Let's Encrypt certificate for $domain..."
sudo certbot renew --non-interactive --quiet    

# 更新 Openfire Keystore
mkdir k.tmp
cd k.tmp
sudo cp /etc/letsencrypt/live/$domain/fullchain.pem fullchain.pem
sudo cp /etc/letsencrypt/live/$domain/privkey.pem privkey.pem
sudo openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out openfire.p12 -name openfire -password pass:changeit
sudo keytool -delete -alias openfire -keystore /usr/share/openfire/resources/security/keystore -storepass changeit
sudo keytool -importkeystore -srckeystore openfire.p12 -srcstoretype PKCS12 -destkeystore /usr/share/openfire/resources/security/keystore -deststoretype JKS -srcstorepass changeit -deststorepass changeit
cd ..
rm -rf k.tmp

# 更新 coturn certificates
sudo cp /etc/letsencrypt/live/$domain/fullchain.pem /etc/coturn/fullchain.pem
sudo cp /etc/letsencrypt/live/$domain/privkey.pem /etc/coturn/privkey.pem 
