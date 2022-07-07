class HeavyHitter:
    """
    Heavy Hitters

    member_variable
    - vector_size : heavy_hitter items의 size
    - items : {id(string): value(integer)} 형식의 dictionary
    
    """
    def __init__(self, vector_size: int = 512) -> None:
        self.vector_size = vector_size
        self.items = dict()
        
    def update(self, item: str) -> int:
        if self.items.get(item): # item is already in heavy hitter
            self.items[item] += 1
            return self.items[item]
        
        # if items is not full
        if len(self.items) < self.vector_size:
            self.items[item] = 1
            return 0
        
        # find the item which has smallest count
        smallest_key = min(self.items, key=self.items.get)
        self.items[item] = self.items.pop(smallest_key) + 1
        return 0

    def fixSubstringFrequency(self) -> None:
        for string1 in self.items.keys():
            for string2 in self.items.keys():
                if string1 != string2 and string1 in string2:
                    self.items[string1] += self.items[string2]

def doubleHeavyHitters(packets:list, k:int = 4, hh1_size:int = 512, hh2_size:int = 512, ratio:float = 0.8) -> dict:
    heavy_hitter1, heavy_hitter2 = HeavyHitter(hh1_size), HeavyHitter(hh2_size)

    for packet in packets:

        s_temp = ""
        temp_count = 0

        h = len(packet)
        for i in range(h-k+1):
            chunk = packet[i:i+k]
            count = heavy_hitter1.update(chunk)
            if count > 0: # case : chunk is in heavy_hiter_1 already
                if s_temp == "":
                    s_temp = chunk
                    temp_count = count
                else:
                    if count > ratio * temp_count:
                        s_temp += packet[i+k-1]
                        temp_count = count
                    else:
                        # reset
                        if s_temp != "":
                            heavy_hitter2.update(s_temp)
                        s_temp = chunk
                        temp_count = count
            else:
                if s_temp != "":
                    heavy_hitter2.update(s_temp)
                # reset temp_count and string
                temp_count = 0
                s_temp = ""
        
        ### append code
        if s_temp != "":
            heavy_hitter2.update(s_temp)

    heavy_hitter2.fixSubstringFrequency()
    return heavy_hitter2.items
