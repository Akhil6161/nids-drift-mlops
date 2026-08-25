from loader import load_dataset


if __name__ == "__main__":
    df = load_dataset()

    print()
    print("First 5 rows:")
    print(df.head())

    print()
    print("Labels:")
    print(df["Label"].value_counts())