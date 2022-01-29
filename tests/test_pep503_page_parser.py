import sys
import unittest

import setup


py_major_version = sys.version_info[0]
htmls = []
cases = []


html = (
    '<!DOCTYPE html>\n<html>\n  <head>\n    <title>Links for frida</title>\n '
    ' </head>\n  <body>\n    <h1>Links for frida</h1>\n    <a href="../../pac'
    'kages/5d/80/3b140c5998df9d81e40169f188a2347b6c705156a2b556ff308e2f8b7e0a'
    '/frida-1.4.1-py2.6-macosx-10.9-intel.egg#sha256=eef92210084ef083b34f8972'
    '078550c6ef45255e444905f95495792c7f709546">frida-1.4.1-py2.6-macosx-10.9-'
    'intel.egg</a><br/>\n<a href="../../packages/4e/ca/ee40ef1d5013300a77152f'
    'f0687caedc3b5ea1f786bf3e0b778de5fc0b8a/frida-9.1.9.tar.gz#sha256=d215884'
    '4cc20cd3e2f8d2cd95f90449f0c27d051d9868706c1eda5d357eb86d7">frida-9.1.9.t'
    'ar.gz</a><br/>\n  </body>\n</html>\n<!--SERIAL 11362971-->'
)
htmls.append(html)
cases.extend([
    (
        setup.PEP503PageParser("frida", "15.1.1", "win-amd64"),
        html,
        []
    ),
    (
        setup.PEP503PageParser("frida", "1.4.1", "macosx-10.9-intel"),
        html,
        [
            setup.ParsedUrlInfo(
                url='../../packages/5d/80/3b140c5998df9d81e40169f188a2347b6c705156a2b556ff308e2f8b7e0a/frida-1.4.1-py2.6-macosx-10.9-intel.egg#sha256=eef92210084ef083b34f8972078550c6ef45255e444905f95495792c7f709546',
                filename='frida-1.4.1-py2.6-macosx-10.9-intel.egg',
                major=2, minor=6, micro=None
            )
        ]
    ),
    (
        setup.PEP503PageParser("frida", "1.4.1", "macosx-11.0-arm64"),
        html,
        []
    ),
])

html = (
    '<a href="../../packages/e3/21/da75f6207f76750799d68938707a74d46512e666293eb550247bf5314613/frida-15.0.7-py2.7-linux-i686.egg#sha256=444246bad3b2222efec301e96c2d6ac5da039d41acd655f6d5b6e548637cae09">frida-15.0.7-py2.7-linux-i686.egg</a><br/>'
    '<a href="../../packages/27/98/751c293b3f246692f3f70ee33c8699ff19f9ded770ae2557ac5641b3456c/frida-15.0.7-py2.7-linux-x86_64.egg#sha256=85547f36d30520b4ecc21bdabd6d6f458367558c5eae12af201bab41451b79c1">frida-15.0.7-py2.7-linux-x86_64.egg</a><br/>'
    '<a href="../../packages/e2/51/8eb9b60736ca600ee466263e1fe6339a1440225d58cb028eae523b30ceac/frida-15.0.7-py2.7-macosx-10.9-x86_64.egg#sha256=123e6ba62f240bb58831196c6d3191cdfc0d76fc12a53c9129805609d595ae3a">frida-15.0.7-py2.7-macosx-10.9-x86_64.egg</a><br/>'
    '<a href="../../packages/9c/c1/692e3a554b3e5929e4a5084fbfc99d64533500f73cbb23b329c283801456/frida-15.0.7-py2.7-macosx-11.0-fat64.egg#sha256=a6bff86e4907a3d5587ca370c7650ba55d4d20f35a6f7884573b129de4f0cc81">frida-15.0.7-py2.7-macosx-11.0-fat64.egg</a><br/>'
    '<a href="../../packages/e0/5c/b45c8f27482d81179eb640726b703f95c624cc4f32ae3ed3f8bc858ae5d9/frida-15.0.7-py2.7-win-amd64.egg#sha256=eb696528b9c19f1895123e731b094363a87a4412d7ea4fcb54ef71841f7b3c1e">frida-15.0.7-py2.7-win-amd64.egg</a><br/>'
    '<a href="../../packages/bb/81/57ff40027efa9309de1a49d64a185637c2151892120d70b90cdb31ae33f0/frida-15.0.7-py2.7-win32.egg#sha256=3110d5400e8cd422540f47fcceccce070d208852cadca9597167166d274e11fa">frida-15.0.7-py2.7-win32.egg</a><br/>'
    '<a href="../../packages/53/c2/f9b94fff26fc2e71af2b92d8295df1e1360895e9fb6f23b82282f38532f9/frida-15.0.7-py3.8-android-aarch64.egg#sha256=a434ed65ea0e2076e67d08528be426532365515b0a051a053833f2b45264151b">frida-15.0.7-py3.8-android-aarch64.egg</a><br/>'
    '<a href="../../packages/19/d3/a4a1980005e232399575aeb2ae973d2087a94ec7dbaf6d7a481612979fc7/frida-15.0.7-py3.8-linux-i686.egg#sha256=ed922ec0258e95f39b4004066b72fb48546041d28602e55d44ca12effa80e8bf">frida-15.0.7-py3.8-linux-i686.egg</a><br/>'
    '<a href="../../packages/9f/cb/496679b506e821bf87ae57f60fd5e4955745b01b2546249f3f00c1fa4678/frida-15.0.7-py3.8-linux-x86_64.egg#sha256=f3419dbf0db069b457d45fd423ccbd0746b184fe39e3d9dd589608db02ca18ab">frida-15.0.7-py3.8-linux-x86_64.egg</a><br/>'
    '<a href="../../packages/6e/80/4d458e4fedcc05b882f0c4bd957d7c2f36b042872f21c6338ef7f9630c89/frida-15.0.7-py3.8-macosx-10.9-x86_64.egg#sha256=695e3e0e914f15e8158b76f59489d983b756d50f22105cc042b1aa232d91568b">frida-15.0.7-py3.8-macosx-10.9-x86_64.egg</a><br/>'
    '<a href="../../packages/15/96/414675d6e7da98b32187995aff8efce06294f3f469b52c97527528fb9eb3/frida-15.0.7-py3.8-macosx-11.0-arm64.egg#sha256=9b0e2bb694c11dab52268a400c7e812b8c53e66147eb05d705d0261c5afc3d52">frida-15.0.7-py3.8-macosx-11.0-arm64.egg</a><br/>'
    '<a href="../../packages/77/34/6ebaea697f3df72818e60c6494a716c51f7f13b3da323598c1711d21779c/frida-15.0.7-py3.8-win-amd64.egg#sha256=a9964cc6dd4e3ea71c42b1800c79571c670905dc82cd769302b066499fff7bf4">frida-15.0.7-py3.8-win-amd64.egg</a><br/>'
    '<a href="../../packages/d2/50/6cf690272c6a2c65f8ebd8fb059d0194d4ffac231fe4e31a0da2456b69a1/frida-15.0.7-py3.8-win32.egg#sha256=99e4b9f06b483c7728eca58bffd07b909733d45311c55ce92c0061d9ea477b69">frida-15.0.7-py3.8-win32.egg</a><br/>'
    '<a href="../../packages/fd/3b/b0285b19ec5b5f3dc3f3d8b5de6a1f4c1c611c47a96f630f0df11da9207b/frida-15.0.7.tar.gz#sha256=1848e4b951cf5fcd5ccb22b9b5ca4a21f121e6b24ac2fba8b91ceec09addd40b">frida-15.0.7.tar.gz</a><br/>'
    '<a href="../../packages/b3/a4/61156ee1b30fae228f1d202a4b8d08aeb31352985da4b33b225f41ec3932/frida-15.0.8-py2.7-linux-aarch64.egg#sha256=6e4e02e61f7a4acc8f372985a86a35f5a5bc2f9b327f063371472fd764d20c92">frida-15.0.8-py2.7-linux-aarch64.egg</a><br/>'
    '<a href="../../packages/fa/c6/4a61609a44ec861986b89c8b6163f27515ef88a4e5876a45c8796457ed7d/frida-15.0.8-py2.7-linux-armv7l.egg#sha256=cac41b6072026f195cd7f3bb4280228e1740a87a5bbccdd5d4054a30f673ac01">frida-15.0.8-py2.7-linux-armv7l.egg</a><br/>'
    '<a href="../../packages/0e/09/0759a0582adba88b29a64599fec3e9f4f8949e62158e72a1ac87af1e92c6/frida-15.0.8-py2.7-linux-i686.egg#sha256=1d8dee7bb788a4cfacb664c6a47107ec4cd651b0b6707abaa2e3f1143eb092d9">frida-15.0.8-py2.7-linux-i686.egg</a><br/>'
    '<a href="../../packages/64/4a/1e1735a8c2f606c953cccfb9d7086c15d19b5151ebd6e0cbcab2e817d6e2/frida-15.0.8-py2.7-linux-x86_64.egg#sha256=e5b29da8394ef5643fc42877856859d544cd2aba0a874a4a700f2ce4521d9780">frida-15.0.8-py2.7-linux-x86_64.egg</a><br/>'
    '<a href="../../packages/d5/05/640d0544779eb011dfc5cea9216eaa617ec2436f31e949f33cad9e5de349/frida-15.0.8-py2.7-macosx-10.9-x86_64.egg#sha256=3ab213b7ae45e45fcb3fbb0d7618568914417400a4248b347f3815c322268232">frida-15.0.8-py2.7-macosx-10.9-x86_64.egg</a><br/>'
    '<a href="../../packages/d1/20/a65170d6a898541839acb03a16d1dd26499928c937350078765fe1e4beb3/frida-15.0.8-py2.7-macosx-11.0-fat64.egg#sha256=f9e58ff7f6d53640a991d3e77711b0095927103d7bdfef55268b58091938f72e">frida-15.0.8-py2.7-macosx-11.0-fat64.egg</a><br/>'
    '<a href="../../packages/5b/50/28a9b1c65ca88f2e5570814db22bdf0fa819f6015fefc97d05878b796fda/frida-15.0.8-py2.7-win-amd64.egg#sha256=2efb63e548773029745e3e057ae4c7647c156af2ed479c5cc31c0167d4c0d9b1">frida-15.0.8-py2.7-win-amd64.egg</a><br/>'
    '<a href="../../packages/72/18/3e36e66989828a7e4e8c4936287f5ba5aa1e2d5a7729e613c22171fdc939/frida-15.0.8-py2.7-win32.egg#sha256=cf0b5ac48f100c73b4eb33533f22eb4e4e2968a3b617c3e3a9671e2f1f7187d2">frida-15.0.8-py2.7-win32.egg</a><br/>'
    '<a href="../../packages/3f/54/bc43a1cb31e5ca7974e38d9eec022d110233baa576b61446036fcfbd652d/frida-15.0.8-py3.6-linux-aarch64.egg#sha256=091f7e5b340f554064a8a675dcdb45f450c8c302f1543f92ccd61b6379ded37c">frida-15.0.8-py3.6-linux-aarch64.egg</a><br/>'
    '<a href="../../packages/21/68/c23ad9197d39f8c953f72b8673ce3832842cbbfea32482712f9b3890c336/frida-15.0.8-py3.6-linux-armv7l.egg#sha256=1a43484f43a86e1adff050b87dedecd3f2a93f0d90d41b13b70427737613f53a">frida-15.0.8-py3.6-linux-armv7l.egg</a><br/>'
    '<a href="../../packages/42/b0/58993429bb518a2c387d8cdb056a1f298fed627658e026a4f625c2e0d2be/frida-15.0.8-py3.8-android-aarch64.egg#sha256=a23853e0f81ce27da5e6cc07082849a673b2c8c148e40f7eaf79392e7181c1e7">frida-15.0.8-py3.8-android-aarch64.egg</a><br/>'
    '<a href="../../packages/f3/5c/1132414e96543b68e0ee986e5d4f5c96ee2be80faf9662862db2a081e065/frida-15.0.8-py3.8-linux-i686.egg#sha256=2dcd57cd6ba60e0ea78edd7a1c1e68ac0c1c34ea8079fa30512a0021d5e7cd1f">frida-15.0.8-py3.8-linux-i686.egg</a><br/>'
    '<a href="../../packages/0b/20/11101c2cc053bbe3695c8778ffb239e49c0bc24066257bc3246ef67770d9/frida-15.0.8-py3.8-linux-x86_64.egg#sha256=6b3f42225c22a1f149107f963abe9f7b5f32eb4915fe8fa8286e5657a7b6c789">frida-15.0.8-py3.8-linux-x86_64.egg</a><br/>'
    '<a href="../../packages/f3/40/6cd6ebfe475c13ef2204f0163233f47611bbcc8b2abc8b38c8a6a34a1040/frida-15.0.8-py3.8-macosx-10.9-x86_64.egg#sha256=861e0463089e3f7c92f1a91e3518c4d3e820cde270c78b76c46f68db859e9022">frida-15.0.8-py3.8-macosx-10.9-x86_64.egg</a><br/>'
    '<a href="../../packages/3d/35/26f4baf9e6916707fd19d6e8df28d87111e782e10b3f0fb369d470212581/frida-15.0.8-py3.8-macosx-11.0-arm64.egg#sha256=ee93a3fe432bf5b877a138d591e7bcd7794b235811967de7e60cef6d76342480">frida-15.0.8-py3.8-macosx-11.0-arm64.egg</a><br/>'
    '<a href="../../packages/6c/1a/d5fc597bd5e09604aa97964d59017591847cb8b9026ee44a1ecf098820b1/frida-15.0.8-py3.8-win-amd64.egg#sha256=f21855d2539f8b82cb579a2cd6683c8443337365ab17b1d0c220fc3ceb6f4c92">frida-15.0.8-py3.8-win-amd64.egg</a><br/>'
    '<a href="../../packages/63/54/35a70eb9212a11fbcf3de83ca89d776733768f7ddada85b69853e5bce2fe/frida-15.0.8-py3.8-win32.egg#sha256=ebc2ba7f0808690c52051f361ef05594107373700b00841e8325129efef0cec2">frida-15.0.8-py3.8-win32.egg</a><br/>'
    '<a href="../../packages/e4/0f/9954d94b174ba703b7018ae01c5e37189715a7b1616a2341794ccbefe834/frida-15.0.8.tar.gz#sha256=de2df2924770601ce39cdc992fa3690b4a0891d614a515cad03bc1b94e762ff1">frida-15.0.8.tar.gz</a><br/>'
)
htmls.append(html)
cases.extend([
    (
        setup.PEP503PageParser("frida", "15.1.0", "win-amd64"),
        html,
        []
    ),
    (
        setup.PEP503PageParser("frida", "15.0.7", "win-amd64"),
        html,
        [
            setup.ParsedUrlInfo(
                url='../../packages/e0/5c/b45c8f27482d81179eb640726b703f95c624cc4f32ae3ed3f8bc858ae5d9/frida-15.0.7-py2.7-win-amd64.egg#sha256=eb696528b9c19f1895123e731b094363a87a4412d7ea4fcb54ef71841f7b3c1e',
                filename='frida-15.0.7-py2.7-win-amd64.egg',
                major=2, minor=7, micro=None
            ),
            setup.ParsedUrlInfo(
                url='../../packages/77/34/6ebaea697f3df72818e60c6494a716c51f7f13b3da323598c1711d21779c/frida-15.0.7-py3.8-win-amd64.egg#sha256=a9964cc6dd4e3ea71c42b1800c79571c670905dc82cd769302b066499fff7bf4',
                filename='frida-15.0.7-py3.8-win-amd64.egg',
                major=3, minor=8, micro=None
            ),
        ]
    ),
    (
        setup.PEP503PageParser("frida", "15.0.7", "linux-i686"),
        html,
        [
            setup.ParsedUrlInfo(
                url='../../packages/e3/21/da75f6207f76750799d68938707a74d46512e666293eb550247bf5314613/frida-15.0.7-py2.7-linux-i686.egg#sha256=444246bad3b2222efec301e96c2d6ac5da039d41acd655f6d5b6e548637cae09',
                filename='frida-15.0.7-py2.7-linux-i686.egg',
                major=2, minor=7, micro=None
            ),
            setup.ParsedUrlInfo(
                url='../../packages/19/d3/a4a1980005e232399575aeb2ae973d2087a94ec7dbaf6d7a481612979fc7/frida-15.0.7-py3.8-linux-i686.egg#sha256=ed922ec0258e95f39b4004066b72fb48546041d28602e55d44ca12effa80e8bf',
                filename='frida-15.0.7-py3.8-linux-i686.egg',
                major=3, minor=8, micro=None
            ),
        ]
    ),
    (
        setup.PEP503PageParser("frida", "15.0.8", "linux-x86_64"),
        html,
        [
            setup.ParsedUrlInfo(
                url='../../packages/64/4a/1e1735a8c2f606c953cccfb9d7086c15d19b5151ebd6e0cbcab2e817d6e2/frida-15.0.8-py2.7-linux-x86_64.egg#sha256=e5b29da8394ef5643fc42877856859d544cd2aba0a874a4a700f2ce4521d9780',
                filename='frida-15.0.8-py2.7-linux-x86_64.egg',
                major=2, minor=7, micro=None
            ),
            setup.ParsedUrlInfo(
                url='../../packages/0b/20/11101c2cc053bbe3695c8778ffb239e49c0bc24066257bc3246ef67770d9/frida-15.0.8-py3.8-linux-x86_64.egg#sha256=6b3f42225c22a1f149107f963abe9f7b5f32eb4915fe8fa8286e5657a7b6c789',
                filename='frida-15.0.8-py3.8-linux-x86_64.egg',
                major=3, minor=8, micro=None
            ),
        ]
    ),
    (
        setup.PEP503PageParser("frida", "15.0.7", "linux-amd64"),
        html,
        []
    ),
    (
        setup.PEP503PageParser("frida", "15.0.8", "macosx-11.0-fat64"),
        html,
        [
            setup.ParsedUrlInfo(
                url='../../packages/d1/20/a65170d6a898541839acb03a16d1dd26499928c937350078765fe1e4beb3/frida-15.0.8-py2.7-macosx-11.0-fat64.egg#sha256=f9e58ff7f6d53640a991d3e77711b0095927103d7bdfef55268b58091938f72e',
                filename='frida-15.0.8-py2.7-macosx-11.0-fat64.egg',
                major=2, minor=7, micro=None
            ),
        ]
    ),
])

html = (
    '<h3>frida-15.1.1-py3.8-linux-x86_64.egg</h3>'
    '<a href="../../packages/e4/c1/82e361bbaa535b334f5b1b432b4573a7871fa973ede'
    'b3aab9dbb6b3b4cdc/frida-15.1.1-py3.8-linux-x86_64.egg#sha256=505f4ffa34cc'
    '7d68664fcd00d469f5d832e6778800d112aadb8a13692f984b40">frida-15.1.1-py3.8-'
    'linux-x86_64.egg</a><br/>'
)
htmls.append(html)
cases.extend([
    (
        setup.PEP503PageParser("frida", "15.1.1", "linux-x86_64"),
        html,
        [
            setup.ParsedUrlInfo(
                url='../../packages/e4/c1/82e361bbaa535b334f5b1b432b4573a7871fa973edeb3aab9dbb6b3b4cdc/frida-15.1.1-py3.8-linux-x86_64.egg#sha256=505f4ffa34cc7d68664fcd00d469f5d832e6778800d112aadb8a13692f984b40',
                filename='frida-15.1.1-py3.8-linux-x86_64.egg',
                major=3, minor=8, micro=None
            ),
        ]
    ),
])

html = (
    '<a role="button" tabindex="0">frida-15.0.1-py3.8-android-aarch64.egg</a>'
    '<a href="../../packages/3e/80/78fa3ed5fd636b606dc06157069b37eb677652cd985'
    '739cde35a86d7a362/frida-15.0.1-py3.8-android-aarch64.egg#sha256=d44bc3415'
    '90dd8cf2623089b54aa16d697536fb016fde0ecd6df5262723c652b">frida-15.0.1-py3'
    '.8-android-aarch64.egg</a><br/>'
)
htmls.append(html)
cases.extend([
    (
        setup.PEP503PageParser("frida", "15.0.1", "android-aarch64"),
        html,
        [
            setup.ParsedUrlInfo(
                url='../../packages/3e/80/78fa3ed5fd636b606dc06157069b37eb677652cd985739cde35a86d7a362/frida-15.0.1-py3.8-android-aarch64.egg#sha256=d44bc341590dd8cf2623089b54aa16d697536fb016fde0ecd6df5262723c652b',
                filename='frida-15.0.1-py3.8-android-aarch64.egg',
                major=3, minor=8, micro=None
            ),
        ]
    ),
])


class TestPEP503PageParser(unittest.TestCase):
    def test_parse_html(self):
        for parser, html, result in cases:
            for _ in range(2):
                parser.reset()
                parser.feed(html)
                assert parser.urls == result, (parser.urls, result)
