package com.ccb.pdf;


import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;

public class ItextUtil {

    public static final char[] PASSWORD = "123456".toCharArray();// keystory密码

    /**
     * 单多次签章通用
     *
     * @param src
     * @param target
     * @param signatureInfos
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws DocumentException
     */
    @SuppressWarnings("resource")
    public void sign(String src, String target, SignatureInfo signatureInfo) {
        InputStream inputStream = null;
        FileOutputStream outputStream = null;
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try {
            inputStream = new FileInputStream(src);
            ByteArrayOutputStream tempArrayOutputStream = new ByteArrayOutputStream();
            PdfReader reader = new PdfReader(inputStream);
            // 创建签章工具PdfStamper ，最后一个boolean参数是否允许被追加签名
            // false的话，pdf文件只允许被签名一次，多次签名，最后一次有效
            // true的话，pdf可以被追加签名，验签工具可以识别出每次签名之后文档是否被修改
            PdfStamper stamper = PdfStamper.createSignature(reader,
                    tempArrayOutputStream, '\0', null, true);
            // 获取数字签章属性对象
            PdfSignatureAppearance appearance = stamper
                    .getSignatureAppearance();
            appearance.setReason(signatureInfo.getReason());
            appearance.setLocation(signatureInfo.getLocation());
            // 设置签名的位置，页码，签名域名称，多次追加签名的时候，签名预名称不能一样 图片大小受表单域大小影响（过小导致压缩）
            // 签名的位置，是图章相对于pdf页面的位置坐标，原点为pdf页面左下角
            // 四个参数的分别是，图章左下角x，图章左下角y，图章右上角x，图章右上角y
            appearance.setVisibleSignature(
                    new Rectangle(signatureInfo.getRectllx(), signatureInfo
                            .getRectlly(), signatureInfo.getRecturx(),
                            signatureInfo.getRectury()), 1, signatureInfo
                            .getFieldName());
            // 读取图章图片
            Image image = Image.getInstance(signatureInfo.getImagePath());
            appearance.setSignatureGraphic(image);
            appearance.setCertificationLevel(signatureInfo
                    .getCertificationLevel());
            // 设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
            appearance.setRenderingMode(signatureInfo.getRenderingMode());
            // 摘要算法

            ExternalDigest digest = new BouncyCastleDigest();
            // 签名算法
            ExternalSignature signature = new PrivateKeySignature(
                    signatureInfo.getPk(), signatureInfo.getDigestAlgorithm(),
                    null);
            // 调用itext签名方法完成pdf签章 //数字签名格式，CMS,CADE
            MakeSignature.signDetached(appearance, digest, signature,
                    signatureInfo.getChain(), null, null, null, 0,
                    MakeSignature.CryptoStandard.CADES);

            inputStream = new ByteArrayInputStream(
                    tempArrayOutputStream.toByteArray());
            // 定义输入流为生成的输出流内容，以完成多次签章的过程
            result = tempArrayOutputStream;

            outputStream = new FileOutputStream(new File(target));
            outputStream.write(result.toByteArray());
            outputStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (null != outputStream) {
                    outputStream.close();
                }
                if (null != inputStream) {
                    inputStream.close();
                }
                if (null != result) {
                    result.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }



public static void setupStemper()  throws Exception {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        //Security.addProvider(bcp);
        Security.insertProviderAt(bcp, 1);
}
public void testVerifyTestMGomez(String pdfname ) throws Exception {

        setupStemper();
        try (InputStream resource = new FileInputStream(pdfname)) {
            PdfReader reader = new PdfReader(resource);
            AcroFields acroFields = reader.getAcroFields();

            List<String> names = acroFields.getSignatureNames();
            for (String name : names) {
                System.out.println("Signature name: " + name);
                System.out.println("Signature covers whole document: " + acroFields.signatureCoversWholeDocument(name));
                PdfPKCS7 pk = acroFields.verifySignature(name);
                System.out.println("Subject: " + CertificateInfo.getSubjectFields(pk.getSigningCertificate()));
                System.out.println("Document verifies: " + pk.verify());
            }
        }

        System.out.println();

        Field rsaDataField = PdfPKCS7.class.getDeclaredField("RSAdata");
        rsaDataField.setAccessible(true);

        try (InputStream resource = new FileInputStream(pdfname)) {
            PdfReader reader = new PdfReader(resource);
            AcroFields acroFields = reader.getAcroFields();

            List<String> names = acroFields.getSignatureNames();
            for (String name : names) {
                System.out.println("Signature name: " + name);
                System.out.println("Signature covers whole document: " + acroFields.signatureCoversWholeDocument(name));
                PdfPKCS7 pk = acroFields.verifySignature(name);
                System.out.println("Subject: " + CertificateInfo.getSubjectFields(pk.getSigningCertificate()));

                Object rsaDataFieldContent = rsaDataField.get(pk);
                if (rsaDataFieldContent != null && ((byte[]) rsaDataFieldContent).length == 0) {
                    System.out.println("Found zero-length encapsulated content: ignoring");
                    rsaDataField.set(pk, null);
                }
                System.out.println("Document verifies: " + pk.verify());
            }
        }
    }



    public static void main(String[] args) {
        try {
            ItextUtil app = new ItextUtil();
            // 将证书文件放入指定路径，并读取keystore ，获得私钥和证书链
            String pkPath = "D:\\git\\java\\qdkafka\\src\\main\\java\\com\\ccb\\tomatocc.p12";
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(pkPath), PASSWORD);
            String alias = ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
            // 得到证书链
            Certificate[] chain = ks.getCertificateChain(alias);
            //需要进行签章的pdf
            String path = "D:/demo.pdf";
            // 封装签章信息
            SignatureInfo signInfo = new SignatureInfo();
            signInfo.setReason("理由");
            signInfo.setLocation("位置");
            signInfo.setPk(pk);
            signInfo.setChain(chain);
            signInfo.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
            signInfo.setDigestAlgorithm(DigestAlgorithms.SHA1);
            signInfo.setFieldName("demo");

            // 签章图片
            signInfo.setImagePath("d:/sign.jpg");
            signInfo.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            signInfo.setRectllx(300);  // 值越大，代表向x轴坐标平移 缩小 （反之，值越小，印章会放大）
            signInfo.setRectlly(90);  // 值越大，代表向y轴坐标向上平移（大小不变）
            signInfo.setRecturx(400);  // 值越大   代表向x轴坐标向右平移  （大小不变）
            signInfo.setRectury(10);  // 值越大，代表向y轴坐标向上平移（大小不变）
            //签章后的pdf路径
            app.sign(path, "D:/demo3.pdf", signInfo);


            app.testVerifyTestMGomez("D:/demo3.pdf");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

