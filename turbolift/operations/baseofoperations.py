# ==============================================================================
# Copyright [2013] [Kevin Carter]
# License Information :
# This software has no warranty, it is provided 'as is'. It is your
# responsibility to validate the behavior of the routines and its accuracy using
# the code provided. Consult the GNU General Public license for further details
# (see GNU General Public License).
# http://www.gnu.org/licenses/gpl.html
# ==============================================================================

import sys
import os
import traceback

from turbolift.operations import getdirsandfiles, compressfiles, getfilenames
from turbolift.operations import cfactions, novacommands, generators


class NoSource(Exception):
    pass


class BaseCamp(object):
    def __init__(self, tur_arg):
        """
        To access the BaseCamp class you will need to provide "tur_arg" which is
        a Dictionary for all of the parsed arguments.

        BaseCamp acts as a simple metthod for seperating out methods from one
        another. With base camp all start points are engaged.
        """
        self.tur_arg = generators.manager_dict(tur_arg)
        try:
            self.nova = novacommands.NovaAuth(tur_arg=self.tur_arg)
            reqjson, auth_url = self.nova.osauth()
            self.nova.make_request(jsonreq=reqjson, url=auth_url)
        except Exception:
            print(traceback.format_exc())
            sys.exit('Authentication against the NOVA API had issues,'
                     ' so I died')

    def set_concurency(self):
        """
        Concurency is a user specified variable when the arguments are parsed.
        However if the number of things Turbo lift has to do is less than the
        desired concurency, then turbolift will lower the concurency rate to
        the number of operations.
        """
        if self.tur_arg.get('cc', 0) > self.tur_arg.get('fc', 1):
            print('MESSAGE\t: There are less things to do than the number of'
                  ' concurrent\n\t  processes specified by either an override'
                  ' or the system defaults.\n\t  I am leveling the number of'
                  ' concurrent processes to the number of\n\t jobs to perform.')
            self.tur_arg['multipools'] = self.tur_arg['fc']
        else:
            self.tur_arg['multipools'] = self.tur_arg['cc']

        if self.tur_arg['verbose']:
            print('MESSAGE\t: We are going to create Processes : %s\n'
                   % (self.tur_arg['multipools']))

    def basic_file_structure(self):
        """
        This is a simple method for understanding the locations for all of
        the files that we are going to uploading
        """
        self.gfn = getfilenames.FileNames(self.tur_arg).get_filenames()
        self.tur_arg['fc'] = len(self.gfn)
        if self.tur_arg.get('verbose'):
            print('MESSAGE\t: "%s" files have been found.' % self.tur_arg['fc'])
        self.set_concurency()

    def con_per_dir(self):
        """
        con_per_dir is a method desigend to upload all of the contents of a
        directory into a container. Using this method will craete a new
        container for all directories found from within a path.
        """
        if os.path.exists(self.tur_arg.get('source')):
            gen_p = getdirsandfiles.GetDirsAndFiles(self.tur_arg)
            pay_load = gen_p.get_dir_and_files()
            self.tur_arg['fc'] = len(pay_load.values())
            self.set_concurency()
            cfactions.CloudFilesActions(tur_arg=self.tur_arg,
                                        pay_load=pay_load.items()).job_prep()
        else:
            raise NoSource('You did not give me a source for the upload')

    def archive(self):
        """
        The archive function was made to simply build a Tarball of all of the
        contents found from within a given path. With this method multiple
        "sources" can be used as they will simply preserve the upload source
        from within the tarball.
        """
        from turbolift.operations import IndicatorThread
        for source in self.tur_arg['source']:
            if not os.path.exists(source):
                raise NoSource('Source Provided is broken or does not exist %s'
                               % source)
        self.basic_file_structure()
        self.tur_arg['multipools'] = 1

        _it = IndicatorThread().indicator_thread()

        _cf = compressfiles.Compressor(self.tur_arg,
                                       self.gfn).compress_files()
        _it.terminate()
        cfs = os.path.getsize(_cf)
        print 'MESSAGE\t: Uploading... %s bytes' % cfs
        pay_load = {self.tur_arg['container']: [_cf]}
        cfactions.CloudFilesActions(tur_arg=self.tur_arg,
                                    pay_load=pay_load.items()).job_prep()

        # Nuke the left over file if there was one.
        if self.tur_arg.get('no_cleanup'):
            print 'MESSAGE\t: Archive Location = %s' % _cf
        else:
            print 'MESSAGE\t: Removing Local Copy of the Archive'
            if os.path.exists(_cf):
                os.remove(_cf)
            else:
                print('File "%s" Did not exist so there was nothing to delete.'
                      % _cf)

    def file_upload(self):
        """
        This is the first and most basic method, using file_upload is to simply
        upload all files and folders to a specified container.
        """
        if os.path.exists(self.tur_arg.get('source')):
            self.basic_file_structure()
            self.pay_load = {self.tur_arg['container']: self.gfn}

            if self.tur_arg.get('debug'):
                print('FILELIST\t: %s\n'
                      'ARGS\t: %s\n' % (self.pay_load, self.tur_arg))

            # Upload our built payload
            cfactions.CloudFilesActions(
                tur_arg=self.tur_arg,
                pay_load=self.pay_load.items()).job_prep()
        else:
            raise NoSource('You did not give me a source for the upload')

    def delete_download(self):
        """
        Downloads all of the files in a container or
        Deletes all of the files in a container
        """
        resp = self.nova.container_check(self.tur_arg.get('container'))
        if resp.status == 404:
            sys.exit('The Container you want to use does not exist')
        cfl = self.nova.get_object_list(self.tur_arg.get('container'))
        self.tur_arg['fc'] = len(cfl)
        print('Processing "%s" Objects' % self.tur_arg['fc'])
        self.set_concurency()
        self.pay_load = {self.tur_arg['container']: cfl}

        if self.tur_arg.get('debug'):
            print('FILELIST\t: %s\n'
                  'ARGS\t: %s\n' % (self.pay_load, self.tur_arg))

        # Run our built payload
        cfactions.CloudFilesActions(tur_arg=self.tur_arg,
                                    pay_load=self.pay_load.items()).job_prep()

        # If we were deleting things check to see that they were deleted
        if self.tur_arg.get('delete'):
            self.check_deleted()

    def check_deleted(self):
        # Pull a file list, if 0 delete container
        cfl = self.nova.get_object_list(self.tur_arg['container'])
        self.tur_arg['fc'] = len(cfl)
        if self.tur_arg.get('fc', 0) > 0:
            print('We found that some scraps from within the '
                  'container that were not removed during the delete operation.'
                  'We are retrying the operation now...')
            self.delete_download()
        else:
            if not self.tur_arg.get('save_container'):
                # Remove the deleted container
                self.nova.container_deleter(self.tur_arg['container'])
                # Check that the container was deleted
                resp = self.nova.container_check(self.tur_arg['container'])
                if not any([resp.status == 404,
                            resp.status == 204]):
                    container = self.tur_arg['container']
                    print('NOVA-API FAILURE ==> INFO: %s %s %s' % (resp.status,
                                                                   resp.reason,
                                                                   container))
                    sys.exit('There was an issue removing the container.')
