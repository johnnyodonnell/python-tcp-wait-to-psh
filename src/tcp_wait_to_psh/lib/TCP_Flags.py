
class TCP_Flags():
    def __init__(self, integer = 0):
        self.fin_flag = (integer & 1) > 0
        self.syn_flag = (integer & 2) > 0
        self.rst_flag = (integer & 4) > 0
        self.psh_flag = (integer & 8) > 0
        self.ack_flag = (integer & 16) > 0
        self.urg_flag = (integer & 32) > 0
        self.ece_flag = (integer & 64) > 0
        self.cwr_flag = (integer & 128) > 0

    def set_fin_flag(self, value):
        self.fin_flag = value

    def set_syn_flag(self, value):
        self.syn_flag = value

    def set_rst_flag(self, value):
        self.rst_flag = value

    def set_psh_flag(self, value):
        self.psh_flag = value

    def set_ack_flag(self, value):
        self.ack_flag = value

    def set_urg_flag(self, value):
        self.urg_flag = value

    def set_ece_flag(self, value):
        self.ece_flag = value

    def set_cwr_flag(self, value):
        self.cwr_flag = value

    def get_fin_flag(self):
        return self.fin_flag

    def get_syn_flag(self):
        return self.syn_flag

    def get_rst_flag(self):
        return self.rst_flag

    def get_psh_flag(self):
        return self.psh_flag

    def get_ack_flag(self):
        return self.ack_flag

    def get_urg_flag(self):
        return self.urg_flag

    def get_ece_flag(self):
        return self.ece_flag

    def get_cwr_flag(self):
        return self.cwr_flag

    def get_integer(self):
        integer = 0
        if (self.fin_flag):
            integer = integer | 1
        if (self.syn_flag):
            integer = integer | 2
        if (self.rst_flag):
            integer = integer | 4
        if (self.psh_flag):
            integer = integer | 8
        if (self.ack_flag):
            integer = integer | 16
        if (self.urg_flag):
            integer = integer | 32
        if (self.ece_flag):
            integer = integer | 64
        if (self.cwr_flag):
            integer = integer | 128
        return integer

