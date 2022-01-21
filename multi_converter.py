import os

from modules import converter_iptables
from modules import converter_snort
from modules import misp_exporter
from modules import utils

if __name__ == '__main__':
    args = utils.setup(os.path.basename(__file__))
    converter_iptables.main(args)
    converter_snort.main(args)
    misp_exporter.main(args)
