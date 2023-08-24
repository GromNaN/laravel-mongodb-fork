<?php

namespace Jenssegers\Mongodb\Tests\Models;

enum MemberStatus: string
{
    case Member = 'MEMBER';
    case Admin = 'ADMIN';
}
