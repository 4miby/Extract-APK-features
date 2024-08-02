import os
from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import Analysis
import pandas as pd
import re
import shutil
import subprocess



def extract_features(apk_path):
    """
    Extract permissions, intent actions, and API calls from an APK file.
    :param apk_path: Path to the APK file
    :return: Tuple containing a list of permissions, a list of intent actions, and a list of API calls
    """
    a, d, dx = AnalyzeAPK(apk_path)

    #Extract permissions
    permissions = a.get_permissions()
    features = [perm.split('.')[-1] for perm in permissions]  # Chỉ lấy tên permission
    # Extract intent actions
    intents = set()
    for method in dx.get_methods():
        for basic_block in method.get_basic_blocks():
            for instruction in basic_block.get_instructions():
                output = instruction.get_output()
                if "android.intent.action" in output:
                    intent_str = output.split(' ')[-1].strip()
                    intent_str = intent_str[9:-1] # Lấy sau phần android.
                    intents.add(intent_str)
    for intent in intents:
        features.append(intent)

    # Extract api call signature:
    return features

if __name__ == "__main__":
    dict_count = {}
    folder_path = "dataset_dir/test"  # Replace with your APK folder path
    apk_files = [f for f in os.listdir(folder_path) if f.endswith('.apk')]
    for apk_file in apk_files:
        apk_path = os.path.join(folder_path, apk_file)
        features = extract_features(apk_path)
        for feature in features:
            if feature in dict_count:
                dict_count[feature]+=1
            else:
                dict_count[feature] = 1
    print(dict_count)
    sorted_dict_count = sorted(dict_count.items(), key=lambda x: x[1], reverse=True)

    # In ra feature xuất hiện giảm dần
    print("Danh sách các features:")
    for key, value in sorted_dict_count:
        print(f"{key}: {value}")

    # Lưu kết quả vào file .txt
    with open('features.txt', 'w', encoding='utf-8') as f:
        for key, value in sorted_dict_count:
            f.write(f"{key}: {value}\n")