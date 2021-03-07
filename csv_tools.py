class CSV_FILE:
    names = []
    def __init__(self, file_name):
        self.file_name = file_name

    def __repr__(self):
        return 'csv file:' + self.file_name

    def __len__(self):
        return 0

    def implementation(self, tokens):
        pass

    def process(self):
        with open(self.file_name, 'r') as fp:
            first = True
            for line in fp:
                if first:  # If the header of the csv
                    first = False
                    continue
                line = line[:-1]
                tokens = line.split(',')
                self.implementation(tokens)

    def to_dic(self):
        csv_lines = []
        global names
        names = []
        with open(self.file_name, 'r') as fp:
            first = True
            for line in fp:
                line = line[:-1]
                tokens = line.split(',')
                if first:
                    first = False
                    for token in tokens:
                        names.append(token);
                    continue
                if len(tokens) < len(names):
                    print("Not enough tokens Line:" + line)
                    continue
                info = {}
                for ind, item in enumerate(names):
                    info[item] = tokens[ind]
                csv_lines.append(info)
    
        return csv_lines


    def insert_dic_line(self, csv_lines, values):
        new_dic = dict(zip(names, values))
        csv_lines.append(new_dic)

    def from_dic(self, csv_lines):
        f = open(self.file_name, 'w') 
        f.write(','.join(names) + '\n')
        for line in csv_lines:
            csv_line = ''
            for key,value in line.items():
                csv_line += value + ','
            csv_line = csv_line[:-1]
            f.write(csv_line + '\n')
        f.close()
