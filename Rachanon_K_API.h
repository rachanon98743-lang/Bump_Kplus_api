#include <Arduino.h>

class Rachanon_K_API {
    private:
        String apiKey;
        String apiSecret;
        String authCode;
        int statusCode = 0;

        String accessToken;
        uint32_t expiresIn;
        uint32_t accessTokenUpdateAt;

        bool verifyToken() ;
        bool genToken() ;
        bool tokenRefresh() ;
        bool getRequestDt() ;

        double lastAmount;
        String lastRef1;
        String lastRef2;
        String lastRef3;
        String lastRef4;
        String partnerTxnUid;
        String partnerId;
        String lastTransactionDate;

    public:
        Rachanon_K_API(String apiKey, String apiSecret, String authCode = "") ;
        
        bool setClock() ;
        bool QRCodeTag30Create(double amount, String ref1, String ref2, String ref3, String ref4, String *qrRawData) ;
        // bool PaymentTransactionInquiryForQRCodeTag30(String billerId, double amount, String ref1, String transactionDate) ;
        bool checkPaymentConfirm(bool *paymentAreConfirm) ;

};

