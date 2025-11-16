#ifndef CRYPTO_H
#define CRYPTO_H

/**
 * @brief Base64 인코딩을 사용해 파일을 인코딩
 * @param input_file 원본 파일 경로
 * @param output_file 인코딩되어 저장될 파일 경로
 * @return 성공 시 0, 실패 시 -1 반환
 */
int encrypt_file_base64(const char *input_file, const char *output_file);

/**
 * @brief Base64 디코딩을 사용해 파일을 디코딩
 * @param input_file 인코딩된 파일 경로
 * @param output_file 디코딩되어 저장될 파일 경로
 * @return 성공 시 0, 실패 시 -1 반환
 */
int decrypt_file_base64(const char *input_file, const char *output_file);

#endif // CRYPTO_H

