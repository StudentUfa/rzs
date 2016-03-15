#!/usr/bin/env python
# -*- coding: utf-8 -*-

from urlparse import urlparse, urlunparse
import sys
import xml.etree.ElementTree as ElementTree
import argparse
import os

import time
import tld

"""
Скрипт для работы с выгрузкой из реестра запрещенных сайтов
"""

__version__ = '0.1.0'
__date__ = '11.03.2016'


class BlockedRecord:
    def __init__(self):
        # Address Block
        self.ip = list()
        self.domain = list()
        self.squid_domain = list()
        self.url = list()
        self.squid_url = list()
        self.https = None
        self.hash = str()
        self.id = None

        # Info Block
        self.add_time = None
        self.entry_type = None
        self.urgancy_type = 0
        self.block_type = 'default'

        self.entry_type_dictionay = {'1': 'реестр ЕАИС', '2': 'реестр НАП', '3': 'реестр 398-ФЗ',
                                     '4': 'реестр 97-ФЗ (организаторы распространения информации)',
                                     '5': 'реестр НАП, постоянная блокировка',
                                     '6': 'реестр нарушителей прав субъектов персональных данных'}

        # Decision Block
        self.decision_date = None
        self.decision_number = None
        self.decision_org = None

    def prepare_url(self, url):
        """
        :param url:
        :return: Экранируем спецсимволы в урлахдля регэкспа
        """
        tmp = url.replace('.', '\.')
        tmp = tmp.replace('[', '\[')
        tmp = tmp.replace(']', '\]')
        tmp = tmp.replace('(', '\(')
        tmp = tmp.replace(')', '\)')
        tmp = tmp.replace('{', '\{')
        tmp = tmp.replace('}', '\}')
        tmp = tmp.replace('?', '\?')
        tmp = tmp.replace('+', '\+')
        tmp = tmp.replace('|', '\|')
        tmp = tmp.replace('^', '\^')
        tmp = tmp.replace('$', '\$')
        return tmp

    def prepare_url_domain(self, url):
        """
        :param url:
        :return:  преобразование урлов в punycode
        """
        https_flag = 0
        url_parts = urlparse(url)
        if url_parts.scheme == 'https':
            https_flag = 1
        if 0 < url_parts.netloc < 64:
            url_parts.netloc.encode('idna')
        ready_url = urlunparse(url_parts)
        return ready_url, https_flag

    def check_url_len(self, url):
        """
        :param url:
        :return: обрезаем длину урлов до 255 символов и убираем финальный слеш если он есть
        """
        tmp_url = url
        if len(tmp_url) > 255:
            tmp_url = tmp_url[:254]
        if tmp_url[-1:].strip() == '/' or tmp_url[-1:].strip() == '\\':
            tmp_url = tmp_url[:-1]
        return tmp_url

    def load(self, current_record):
        if 'blockType' in current_record.attrib.keys():
            self.block_type = current_record.attrib['blockType']
        if 'urgencyType' in current_record.attrib.keys():
            self.urgancy_type = current_record.attrib['urgencyType']

        self.entry_type = current_record.attrib['entryType']
        self.add_time = current_record.attrib['includeTime']
        self.id = current_record.attrib['id']

        try:
            self.hash = current_record.attrib['hash']
        except AttributeError:
            pass

        try:
            for tmp in current_record.iter('url'):
                tmp_url, self.https = self.prepare_url_domain(tmp.text)
                tmp_url = self.prepare_url(tmp_url)
                tmp_url = self.check_url_len(tmp_url)
                self.squid_url.append(tmp_url.encode('utf8'))
                self.url.append(tmp.text.encode('utf8'))
        except AttributeError:
            print "ERRROR"

        try:
            for tmp in current_record.iter('domain'):
                self.domain.append(tmp.text.encode('utf8'))
                if 0 < len(tmp.text) < 64:
                    self.squid_domain.append(tmp.text.encode('idna').decode('utf8'))
                else:
                    self.squid_domain.append(tmp.text)
        except AttributeError:
            pass

        try:
            for tmp in current_record.iter('ip'):
                self.ip.append(tmp.text)
        except AttributeError:
            pass

        try:
            decision = current_record.find('decision')
            self.decision_date = decision.attrib['date']
            self.decision_number = decision.attrib['number']
            self.decision_org = decision.attrib['org']
        except AttributeError:
            pass

    def output_record(self):
        print '-------------------------------------------------'
        print 'Decision org: %s' % self.decision_org
        print 'Decision date: %s' % self.decision_date
        print 'Decision number: %s' % self.decision_number

        print 'Add time: %s' % self.add_time
        print 'Entry type: %s (%s)' % (self.entry_type_dictionay[self.entry_type], self.entry_type)
        print 'Urgancy: %s' % ('Yes' if self.urgancy_type else 'No')
        print 'Block type: %s' % self.block_type

        print 'IP: %s' % ('Empty' if self.ip is None else ', '.join(self.ip))
        print 'Domain: %s' % ('Empty' if self.domain is None else ', '.join(self.domain))
        print 'URL: %s' % ('Empty' if len(self.url) == 0 else self.url)
        print 'HTTPS: %s' % ('No' if self.https is None else 'Yes')

        if len(self.domain) > 1:
            sys.exit()


class RecordActions:
    def __init__(self):
        self.domain_list = list()
        self.urls_list = list()
        self.squid_urls_list = list()
        self.squid_domain_list = list()
        self.ip_list = list()
        self.https_list = list()
        self.records_list = list()

        self.affected_ip = list()
        self.block_by_ip = list()

    def show_stats(self):
        print 'Domain: %s' % len(self.domain_list)
        print 'IP: %s' % len(self.ip_list)
        print 'URL: %s' % len(self.urls_list)
        print 'HTTPS: %s' % len(self.https_list)
        print '----=Total=----'
        print 'Affected ip: %s' % len(self.affected_ip)
        print 'Blocked ip: %s' % len(self.block_by_ip)

    def load_from_xml(self, dump_file):
        tree = ElementTree.parse(dump_file)
        root = tree.getroot()

        for child in root.findall('content'):
            cur_record = BlockedRecord()
            cur_record.load(child)
            self.records_list.append(cur_record)

            if cur_record.block_type == 'default':
                if cur_record.url != '':
                    for tmp in cur_record.url:
                        self.urls_list.append(tmp)
                    for tmp in cur_record.squid_url:
                        self.squid_urls_list.append(tmp)
                    for tmp in cur_record.ip:
                        self.affected_ip.append(tmp)
                elif cur_record.domain != '':
                    for tmp in cur_record.domain:
                        self.domain_list.append(tmp)
                    for tmp in cur_record.ip:
                        self.affected_ip.append(tmp)
                else:
                    for tmp in cur_record.ip:
                        self.ip_list.append(tmp)
                        self.block_by_ip.append(tmp)
            elif cur_record.block_type == 'domain':
                for tmp in cur_record.domain:
                    self.domain_list.append(tmp)
                for tmp in cur_record.squid_domain:
                    self.squid_domain_list.append(tmp)
                for tmp in cur_record.ip:
                    self.affected_ip.append(tmp)
            elif cur_record.block_type == 'url':
                for tmp in cur_record.squid_url:
                    self.squid_urls_list.append(tmp)
                for tmp in cur_record.url:
                    self.urls_list.append(tmp)
                for tmp in cur_record.ip:
                    self.affected_ip.append(tmp)
            elif cur_record.block_type == 'ip':
                for tmp in cur_record.ip:
                    self.ip_list.append(tmp)
                    self.block_by_ip.append(tmp)
            if cur_record.https:
                for tmp in cur_record.ip:
                    self.ip_list.append(tmp)
                    self.https_list.append(tmp)
                    self.block_by_ip.append(tmp)

        self.domain_list = list(set(self.domain_list))
        self.squid_domain_list = list(set(self.squid_domain_list))
        self.ip_list = list(set(self.ip_list))
        self.urls_list = list(set(self.urls_list))
        self.squid_urls_list = list(set(self.squid_urls_list))
        self.https_list = list(set(self.https_list))
        self.affected_ip = list(set(self.affected_ip))
        self.block_by_ip = list(set(self.block_by_ip))

    def find_ip(self, ip):
        find_flag = False
        for cur_record in self.records_list:
            if ip in cur_record.ip:
                find_flag = True
                cur_record.output_record()
        if not find_flag:
            print u'Запись не найдена'

    def find_url(self, url):
        find_flag = False
        for cur_record in self.records_list:
            if url in cur_record.url:
                find_flag = True
                cur_record.output_record()
        if not find_flag:
            print u'Запись не найдена'

    def find_domain(self, domain):
        find_flag = False
        for cur_record in self.records_list:
            if domain in cur_record.domain:
                find_flag = True
                cur_record.output_record()
        if not find_flag:
            print u'Запись не найдена'

    def print_blocked_ip(self):
        print '\n'.join(self.block_by_ip)

    def print_affected_ip(self):
        print '\n'.join(self.affected_ip)

    def print_redirect_ip(self):
        print '\n'.join(list(set(self.affected_ip) - set(self.block_by_ip)))

    def check_subdomain(self, domain):
        pass

    def print_domain(self, squid_flag=False):
        if squid_flag:
            squid_res_list = list()
            for cur_domain in sorted(self.squid_domain_list, key=len):
                try:
                    tmp_domain = tld.get_tld('http://'+cur_domain, as_object=True)
                    if tmp_domain.subdomain == '':
                        if tmp_domain.tld not in squid_res_list:
                            squid_res_list.append(cur_domain)
                    else:
                        blank = ''
                        for subdomain in reversed(tmp_domain.subdomain.split('.')):
                            blank = '.'.join([subdomain, blank])
                            if tmp_domain.tld in squid_res_list:
                                break
                            elif blank+tmp_domain.tld in squid_res_list:
                                break
                            elif blank+tmp_domain.tld not in squid_res_list and blank[:-1] != tmp_domain.subdomain:
                                continue
                            else:
                                squid_res_list.append(cur_domain)
                except tld.exceptions.TldDomainNotFound:
                    squid_res_list.append(cur_domain)
            for row in squid_res_list:
                print '.%s' % row
        else:
            print '\n'.join(sorted(self.domain_list, key=len)).decode('utf8')

    def print_url(self, squid_flag=False):
        if squid_flag:
            for cur_url in self.squid_urls_list:
                print '^%s' % cur_url
        else:
            print '\n'.join(self.urls_list)

parent_parser = argparse.ArgumentParser(add_help=u'Скрипт разбора и анализа выгрзуки из единого реестра')
parent_parser.add_argument('--stats', dest='stats_flag', action="store_true", help=u'Показывает общую статистику')
parent_parser.add_argument('--all_ip', dest='all_flag', action="store_true", help=u'Все затронутые IP')
parent_parser.add_argument('--redirect_ip', dest='redirect_flag', action="store_true",
                           help=u'Список IP для блокировки урлов')
parent_parser.add_argument('--blocked_ip', dest='blocked_flag', action="store_true",
                           help=u'Список IP для полной блокировки, сюда же входят https хосты')
parent_parser.add_argument('--domain', dest='domain_flag', action="store_true", help=u'Список доменов для блокировки')
parent_parser.add_argument('--url', dest='url_flag', action="store_true", help=u'Список URL для блокировки')
parent_parser.add_argument('--find_ip', dest='find_ip', action="store", help=u'Поиск по IP в реестре', metavar='IP')
parent_parser.add_argument('--find_domain', dest='find_domain', action="store", help=u'Поиск по Domain в реестре',
                           metavar='DOMAIN')
parent_parser.add_argument('--find_url', dest='find_url', action="store", help=u'Поиск по URL в реестре', metavar='URL')
parent_parser.add_argument('--squid', dest='squid_flag', action="store_true", help=u'В формате для squid acl ')
parent_parser.set_defaults(suiqd_flag=False)
parent_parser.add_argument('dump_file', nargs='?', type=str, help=u'Путь до xml выгрузки от РосКомНадзора', default='')

if __name__ == '__main__':
    start_time = time.time()
    args = parent_parser.parse_args()
    if os.path.isfile(args.dump_file):
        CurDbRecords = RecordActions()
        CurDbRecords.load_from_xml(args.dump_file)
        if args.stats_flag:
            CurDbRecords.show_stats()
        elif args.all_flag:
            CurDbRecords.print_affected_ip()
        elif args.redirect_flag:
            CurDbRecords.print_redirect_ip()
        elif args.blocked_flag:
            CurDbRecords.print_blocked_ip()
        elif args.domain_flag:
            CurDbRecords.print_domain(args.squid_flag)
        elif args.url_flag:
            CurDbRecords.print_url(args.squid_flag)
        elif args.find_domain is not None:
            CurDbRecords.find_domain(args.find_domain)
        elif args.find_ip is not None:
            CurDbRecords.find_ip(args.find_ip)
        elif args.find_url is not None:
            CurDbRecords.find_url(args.find_url)
