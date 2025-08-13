import numpy as np
import cv2
import matplotlib.pyplot as plt

# 水印嵌入
def embed_watermark(image_path, watermark_path, alpha=0.1):
    # 读取原始图片和水印
    image = cv2.imread(image_path)
    watermark = cv2.imread(watermark_path, cv2.IMREAD_GRAYSCALE)
    
    # 确保水印大小和原图一样
    watermark = cv2.resize(watermark, (image.shape[1], image.shape[0]))
    
    # 将水印转化为二值图像
    _, watermark = cv2.threshold(watermark, 128, 255, cv2.THRESH_BINARY)
    
    # 水印嵌入过程：将水印与原图合成
    watermark = watermark.astype(np.float32) / 255.0  # 转换为0-1之间
    image = image.astype(np.float32) / 255.0  # 转换为0-1之间
    
    watermarked_image = image + alpha * np.dstack([watermark] * 3)  # 对RGB通道分别添加水印
    watermarked_image = np.clip(watermarked_image, 0, 1) * 255  # 限制像素值在0-255之间
    return watermarked_image.astype(np.uint8)

# 水印提取
def extract_watermark(original_image_path, watermarked_image_path, alpha=0.1):
    # 读取原始图片和加水印的图片
    original_image = cv2.imread(original_image_path)
    watermarked_image = cv2.imread(watermarked_image_path)
    
    # 转换为浮动表示
    original_image = original_image.astype(np.float32) / 255.0
    watermarked_image = watermarked_image.astype(np.float32) / 255.0
    
    # 提取水印（通过求差异）
    extracted_watermark = (watermarked_image - original_image) / alpha
    extracted_watermark = np.clip(extracted_watermark, 0, 1) * 255
    return extracted_watermark.astype(np.uint8)

# 鲁棒性测试：图像变换
def apply_transformations(image):
    # 翻转（水平翻转）
    flipped_image = cv2.flip(image, 1)  # 水平翻转
    
    # 平移（向右下平移50像素）
    rows, cols = image.shape[:2]
    M = np.float32([[1, 0, 50], [0, 1, 50]])  # 平移矩阵
    translated_image = cv2.warpAffine(image, M, (cols, rows))
    
    # 截取（裁剪图像的中心区域）
    crop_image = image[50:450, 50:450]  # 假设裁剪中心区域
    
    # 调整对比度（增加对比度和亮度）
    alpha = 2.0  # 对比度倍数
    beta = 50    # 亮度偏移
    contrast_image = cv2.convertScaleAbs(image, alpha=alpha, beta=beta)
    
    return flipped_image, translated_image, crop_image, contrast_image

# 显示变换后的图像
def show_images(original, flipped, translated, cropped, contrast):
    plt.figure(figsize=(12, 8))

    plt.subplot(2, 3, 1)
    plt.imshow(cv2.cvtColor(original, cv2.COLOR_BGR2RGB))
    plt.title('Original Image')
    
    plt.subplot(2, 3, 2)
    plt.imshow(cv2.cvtColor(flipped, cv2.COLOR_BGR2RGB))
    plt.title('Flipped Image')
    
    plt.subplot(2, 3, 3)
    plt.imshow(cv2.cvtColor(translated, cv2.COLOR_BGR2RGB))
    plt.title('Translated Image')
    
    plt.subplot(2, 3, 4)
    plt.imshow(cv2.cvtColor(cropped, cv2.COLOR_BGR2RGB))
    plt.title('Cropped Image')
    
    plt.subplot(2, 3, 5)
    plt.imshow(cv2.cvtColor(contrast, cv2.COLOR_BGR2RGB))
    plt.title('Contrast Adjusted Image')
    
    plt.show()

# 路径设置
image_path = '/kaggle/input/watermarkimage/original_image-512x512.jpg'
watermark_path = '/kaggle/input/watermarkimage/watermark.png'

# 嵌入水印
watermarked_image = embed_watermark(image_path, watermark_path)
cv2.imwrite('/kaggle/working/watermarked_image.jpg', watermarked_image)

# 提取水印
extracted_watermark = extract_watermark(image_path, '/kaggle/working/watermarked_image.jpg')
cv2.imwrite('/kaggle/working/extracted_watermark.jpg', extracted_watermark)

# 进行鲁棒性测试
test_image = cv2.imread('/kaggle/working/watermarked_image.jpg')

flipped_image, translated_image, cropped_image, contrast_image = apply_transformations(test_image)

# 显示结果
show_images(test_image, flipped_image, translated_image, cropped_image, contrast_image)

# 提取水印并显示对比
extracted_from_flipped = extract_watermark(image_path, '/kaggle/working/flipped_image.jpg')
extracted_from_translated = extract_watermark(image_path, '/kaggle/working/translated_image.jpg')
extracted_from_cropped = extract_watermark(image_path, '/kaggle/working/cropped_image.jpg')
extracted_from_contrast = extract_watermark(image_path, '/kaggle/working/contrast_image.jpg')
