import logging

# First logger
logger = logging.getLogger("khanhtv")
logger.setLevel(logging.DEBUG)

file_handler1 = logging.FileHandler("/opt/stack/neutron-fwaas/neutron_fwaas/temp.log")
file_handler1.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler1.setFormatter(formatter)

logger.addHandler(file_handler1)

