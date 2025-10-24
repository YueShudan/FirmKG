import csv
import os

def process_edges_file(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        output_data = [['Source', 'Target', 'Relation', 'Label', 'Color']]
        for row in reader:
            if len(row) >= 4:
                src = row[0]
                tgt = row[1]
                label = row[2]
                color = row[3]
                src_parts = src.split('@')
                tgt_parts = tgt.split('@')
                if len(src_parts) >= 2 and len(tgt_parts) >= 2:
                    src_func = src_parts[0]
                    src_node = src_parts[1]
                    tgt_func = tgt_parts[0]
                    tgt_node = tgt_parts[1]
                    # Relation only the function name
                    new_row = [src_node, tgt_node, f"{src_func}/{tgt_func}", label, color]
                    output_data.append(new_row)
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(output_data)
    print(f"Processing completed: {input_file} -> {output_file}")

def main():
    csv_dir = 'csv'
    results_dir = 'Results'
    os.makedirs(results_dir, exist_ok=True)
    for filename in os.listdir(csv_dir):
        if filename.endswith('_edges.csv'):
            input_file = os.path.join(csv_dir, filename)
            output_file = os.path.join(results_dir, filename.replace('_edges.csv', '_edges.csv'))
            process_edges_file(input_file, output_file)

if __name__ == '__main__':
    main()
