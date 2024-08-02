import os
from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import Analysis
import pandas as pd
import re
import shutil
import subprocess
def get_the_features_names(file_path):
    columns_name = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.split(":")
            if len(line) >=2:
                if(int(line[1]) <= 5):
                    break
                else:
                    columns_name.append(line[0])
    return columns_name


def create_new_dataframe(column_names):
    """
    Create a new DataFrame using the list as column names.
    :param column_names: List to be used as column names of the DataFrame
    :return: New DataFrame with the list as column names
    """
    # Create an empty DataFrame with the specified column names
    new_df = pd.DataFrame(columns=column_names)
    return new_df


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

def extract_api_calls(smali_folder):
    api_calls = set()
    pattern =  re.compile(r"(L[\w\/\$-]+;->[\w$<>]+\(.*?\))([^\s;]*)")

    for root, dirs, files in os.walk(smali_folder):
        for file in files:
            if file.endswith('.smali'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if 'invoke-' in line:
                            match = pattern.search(line)
                            if match:
                                api_call = match.group(1)
                                api_call = api_call.replace('/', '.')  # Thay thế '/' bằng '.'
                                api_calls.add(api_call)

    return list(api_calls)


def extract_api_call_from_smali(apk_path):
    temp_folder = 'temp_folder'

    # Xóa thư mục tạm nếu đã tồn tại
    if os.path.exists(temp_folder):
        shutil.rmtree(temp_folder)

    # Giải nén APK bằng Apktool
    apktool_cmd = f'apktool d {apk_path} -o {temp_folder}'
    process = subprocess.Popen(apktool_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    process.communicate(input=b'\n')  # Tự động trả lời prompt

    # Trích xuất các API call từ thư mục smali
    smali_folder = os.path.join(temp_folder, 'smali')
    api_calls = extract_api_calls(smali_folder)

    return api_calls


def save_to_df(df,features,label):
    new_row = {}
    for col in df.columns:
        if col in features:
            new_row[col] = 1
        else:
            new_row[col] = 0
    new_row['class'] = label
    df = df._append(new_row,ignore_index=True)
    return  df


if __name__ == "__main__":
    column_names_list = get_the_features_names("features.txt")
    print(column_names_list)
    new_df = create_new_dataframe(column_names_list)
    folder_path = "dataset_dir/worm" # Replace with your APK folder path
    apk_files = [f for f in os.listdir(folder_path) if f.endswith('.apk')]
    for apk_file in apk_files:
        apk_path = os.path.join(folder_path, apk_file)
        features = extract_features(apk_path)
        print(features)
        new_df = save_to_df(new_df, features,'S')

    new_df.to_csv('worm.csv')
    print("csv has been save")


